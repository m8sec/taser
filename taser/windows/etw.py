"""Reusable ETW provider enumeration and permission helpers."""

from __future__ import annotations

import csv
import ctypes
import getpass
import json
import os
import platform
import re
import subprocess
import tempfile
import time
import uuid
from ctypes import wintypes
from typing import Dict, Iterable, List, Optional

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows import guard
    winreg = None


ETW_PERMISSION_DEFINITIONS = [
    {"name": "WMIGUID_QUERY", "value": 0x00000001, "description": "Query provider information"},
    {"name": "WMIGUID_SET", "value": 0x00000002, "description": "Modify provider settings"},
    {"name": "WMIGUID_NOTIFICATION", "value": 0x00000004, "description": "Receive notifications"},
    {"name": "WMIGUID_READ_DESCRIPTION", "value": 0x00000008, "description": "Read provider descriptions"},
    {"name": "WMIGUID_EXECUTE", "value": 0x00000010, "description": "Execute provider operations"},
    {"name": "TRACELOG_CREATE_REALTIME", "value": 0x00000020, "description": "Create real-time trace sessions"},
    {"name": "TRACELOG_CREATE_ONDISK", "value": 0x00000040, "description": "Create on-disk trace sessions"},
    {"name": "TRACELOG_GUID_ENABLE", "value": 0x00000080, "description": "Enable provider GUIDs"},
    {"name": "TRACELOG_ACCESS_KERNEL_LOGGER", "value": 0x00000100, "description": "Access kernel logger"},
    {"name": "TRACELOG_CREATE_INPROC", "value": 0x00000200, "description": "Create in-process trace sessions"},
    {"name": "TRACELOG_LOG_EVENT", "value": 0x00000400, "description": "Log events"},
    {"name": "TRACELOG_REGISTER_GUIDS", "value": 0x00000800, "description": "Register provider GUIDs"},
    {"name": "TRACELOG_JOIN_GROUP", "value": 0x00001000, "description": "Join trace groups"},
]


DEFAULT_PROVIDER_ACES = [
    {"type": "Allow", "account": "Everyone", "sid": "WD", "access_mask": 0x00000800},
    {"type": "Allow", "account": "SYSTEM", "sid": "SY", "access_mask": 0x00001FFF},
    {"type": "Allow", "account": "LOCAL SERVICE", "sid": "LS", "access_mask": 0x00001FFF},
    {"type": "Allow", "account": "NETWORK SERVICE", "sid": "NS", "access_mask": 0x00001FFF},
    {"type": "Allow", "account": "Administrators", "sid": "BA", "access_mask": 0x00001FFF},
    {"type": "Allow", "account": "Performance Log Users", "sid": "S-1-5-32-559", "access_mask": 0x00001FEF},
    {"type": "Allow", "account": "Performance Monitor Users", "sid": "S-1-5-32-558", "access_mask": 0x0000000D},
]


_PERMISSION_LOOKUP = {item["name"]: item for item in ETW_PERMISSION_DEFINITIONS}
_SID_ALIAS_MAP = {
    "AO": "Account Operators",
    "AU": "Authenticated Users",
    "BA": "Administrators",
    "BG": "Guests",
    "BO": "Backup Operators",
    "BU": "Users",
    "DA": "Domain Administrators",
    "DG": "Domain Guests",
    "DU": "Domain Users",
    "EA": "Enterprise Administrators",
    "LS": "LOCAL SERVICE",
    "NS": "NETWORK SERVICE",
    "NU": "Network",
    "PA": "Group Policy Administrators",
    "PU": "Power Users",
    "RC": "Restricted Code",
    "RU": "Alias to allow previous Windows 2000",
    "SO": "Server Operators",
    "SU": "Service",
    "SY": "SYSTEM",
    "WD": "Everyone",
}

_WMI_SECURITY_PATH = r"SYSTEM\CurrentControlSet\Control\WMI\Security"
_GUID_RE = re.compile(
    r"^\{?[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\}?$"
)

_REGISTRY_PROVIDER_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE if winreg else None, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers", "name"),
    (winreg.HKEY_LOCAL_MACHINE if winreg else None, r"SYSTEM\CurrentControlSet\Control\WMI\Autologger", "subkey"),
    (winreg.HKEY_LOCAL_MACHINE if winreg else None, r"SOFTWARE\Microsoft\WBEM\Providers", "guid_values"),
    (winreg.HKEY_LOCAL_MACHINE if winreg else None, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\WMI\Security", "guid_values"),
]

ERROR_INSUFFICIENT_BUFFER = 122
SDDL_REVISION_1 = 1
DACL_SECURITY_INFORMATION = 0x00000004
WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_CONTROL_QUERY = 0
EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
TRACE_LEVEL_VERBOSE = 0xFF


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [
        ("BufferSize", wintypes.ULONG),
        ("ProviderId", wintypes.ULONG),
        ("HistoricalContext", ctypes.c_ulonglong),
        ("TimeStamp", ctypes.c_longlong),
        ("Guid", GUID),
        ("ClientContext", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
    ]


class TRACE_PROVIDER_INFO(ctypes.Structure):
    _fields_ = [
        ("ProviderGuid", GUID),
        ("SchemaSource", wintypes.ULONG),
        ("ProviderNameOffset", wintypes.ULONG),
    ]


class PROVIDER_ENUMERATION_INFO(ctypes.Structure):
    _fields_ = [
        ("NumberOfProviders", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", wintypes.ULONG),
        ("MinimumBuffers", wintypes.ULONG),
        ("MaximumBuffers", wintypes.ULONG),
        ("MaximumFileSize", wintypes.ULONG),
        ("LogFileMode", wintypes.ULONG),
        ("FlushTimer", wintypes.ULONG),
        ("EnableFlags", wintypes.ULONG),
        ("AgeLimit", wintypes.LONG),
        ("NumberOfBuffers", wintypes.ULONG),
        ("FreeBuffers", wintypes.ULONG),
        ("EventsLost", wintypes.ULONG),
        ("BuffersWritten", wintypes.ULONG),
        ("LogBuffersLost", wintypes.ULONG),
        ("RealTimeBuffersLost", wintypes.ULONG),
        ("LoggerThreadId", wintypes.HANDLE),
        ("LogFileNameOffset", wintypes.ULONG),
        ("LoggerNameOffset", wintypes.ULONG),
    ]


class EVENT_TRACE_PROPERTIES_WITH_NAME(ctypes.Structure):
    _fields_ = [
        ("Properties", EVENT_TRACE_PROPERTIES),
        ("LoggerName", wintypes.WCHAR * 1024),
        ("LogFileName", wintypes.WCHAR * 1024),
    ]


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def _normalize_guid(value: str) -> str:
    if not value:
        return ""
    value = value.strip().strip("{}").lower()
    return "{" + value + "}"


def _guid_to_string(guid: GUID) -> str:
    data4 = bytes(guid.Data4)
    return "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}".format(
        guid.Data1,
        guid.Data2,
        guid.Data3,
        data4[0],
        data4[1],
        data4[2],
        data4[3],
        data4[4],
        data4[5],
        data4[6],
        data4[7],
    )


def _read_wstr_from_buffer(buffer: ctypes.Array, offset: int) -> str:
    base = ctypes.addressof(buffer)
    return ctypes.wstring_at(base + offset)


def _tdh_enumerate_providers() -> List[Dict[str, object]]:
    tdh = ctypes.WinDLL("tdh")
    buffer_size = wintypes.ULONG(0)
    result = tdh.TdhEnumerateProviders(None, ctypes.byref(buffer_size))
    if result not in (0, ERROR_INSUFFICIENT_BUFFER):
        raise OSError("TdhEnumerateProviders failed with status {}".format(result))

    raw_buffer = ctypes.create_string_buffer(buffer_size.value)
    result = tdh.TdhEnumerateProviders(raw_buffer, ctypes.byref(buffer_size))
    if result != 0:
        raise OSError("TdhEnumerateProviders failed with status {}".format(result))

    header = PROVIDER_ENUMERATION_INFO.from_buffer(raw_buffer)
    array_offset = ctypes.sizeof(PROVIDER_ENUMERATION_INFO)
    providers = []
    for index in range(header.NumberOfProviders):
        item_offset = array_offset + (index * ctypes.sizeof(TRACE_PROVIDER_INFO))
        provider = TRACE_PROVIDER_INFO.from_buffer(raw_buffer, item_offset)
        providers.append(
            {
                "guid": _normalize_guid(_guid_to_string(provider.ProviderGuid)),
                "name": _read_wstr_from_buffer(raw_buffer, provider.ProviderNameOffset),
                "schema_source": int(provider.SchemaSource),
                "source": "tdh",
            }
        )
    return providers


def _run_provider_fallback() -> List[Dict[str, object]]:
    commands = (
        ["logman", "query", "providers"],
        ["wevtutil", "ep"],
    )
    for command in commands:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
        providers = []
        for line in completed.stdout.splitlines():
            value = line.strip()
            if not value or value.lower().startswith(("provider", "pid", "the command")):
                continue
            if command[0] == "logman":
                match = re.match(r"^(?P<name>.+?)\s+\{(?P<guid>[0-9a-fA-F-]{36})\}$", value)
                if match:
                    providers.append(
                        {
                            "guid": _normalize_guid(match.group("guid")),
                            "name": match.group("name").strip(),
                            "schema_source": None,
                            "source": "logman",
                        }
                    )
            else:
                providers.append(
                    {
                        "guid": "",
                        "name": value,
                        "schema_source": None,
                        "source": "wevtutil",
                    }
                )
        if providers:
            return providers
    return []


def _safe_query_value(key, value_name: str):
    try:
        return winreg.QueryValueEx(key, value_name)[0]
    except OSError:
        return None


def _iter_registry_subkeys(root, path: str):
    try:
        key = winreg.OpenKey(root, path)
    except OSError:
        return
    with key:
        count, _, _ = winreg.QueryInfoKey(key)
        for index in range(count):
            try:
                yield winreg.EnumKey(key, index)
            except OSError:
                continue


def _iter_registry_values(root, path: str):
    try:
        key = winreg.OpenKey(root, path)
    except OSError:
        return
    with key:
        _, value_count, _ = winreg.QueryInfoKey(key)
        for index in range(value_count):
            try:
                yield winreg.EnumValue(key, index)
            except OSError:
                continue


def _load_registry_name_map() -> Dict[str, str]:
    if not is_windows() or winreg is None:
        return {}

    names = {}

    for subkey in _iter_registry_subkeys(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers") or []:
        guid = _normalize_guid(subkey)
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{}".format(subkey))
        except OSError:
            continue
        with key:
            name = _safe_query_value(key, "ResourceFileName") or _safe_query_value(key, "MessageFileName") or subkey
            names.setdefault(guid, os.path.basename(str(name)) if name else subkey)

    for subkey in _iter_registry_subkeys(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\WMI\Autologger") or []:
        key_path = r"SYSTEM\CurrentControlSet\Control\WMI\Autologger\{}".format(subkey)
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        except OSError:
            continue
        with key:
            guid = _safe_query_value(key, "Guid") or _safe_query_value(key, "ProviderGuid")
            if isinstance(guid, str) and _GUID_RE.match(guid):
                names.setdefault(_normalize_guid(guid), subkey)

    for value_name, value_data, _ in _iter_registry_values(winreg.HKEY_LOCAL_MACHINE, _WMI_SECURITY_PATH) or []:
        if _GUID_RE.match(value_name):
            names.setdefault(_normalize_guid(value_name), value_name)

    for value_name, value_data, _ in _iter_registry_values(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\WMI\Security",
    ) or []:
        if _GUID_RE.match(value_name) and isinstance(value_data, str):
            names.setdefault(_normalize_guid(value_name), value_data)

    return names


def _lookup_account_name_from_sid_string(sid_string: str) -> Optional[str]:
    if not is_windows():
        return None
    if sid_string in _SID_ALIAS_MAP:
        return _SID_ALIAS_MAP[sid_string]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ConvertStringSidToSidW = advapi32.ConvertStringSidToSidW
    LookupAccountSidW = advapi32.LookupAccountSidW
    LocalFree = kernel32.LocalFree

    sid_ptr = wintypes.LPVOID()
    if not ConvertStringSidToSidW(wintypes.LPCWSTR(sid_string), ctypes.byref(sid_ptr)):
        return None

    try:
        name_size = wintypes.DWORD(0)
        domain_size = wintypes.DWORD(0)
        sid_name_use = wintypes.DWORD(0)
        LookupAccountSidW(None, sid_ptr, None, ctypes.byref(name_size), None, ctypes.byref(domain_size), ctypes.byref(sid_name_use))
        if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER:
            return None

        name_buffer = ctypes.create_unicode_buffer(name_size.value)
        domain_buffer = ctypes.create_unicode_buffer(domain_size.value)
        if not LookupAccountSidW(
            None,
            sid_ptr,
            name_buffer,
            ctypes.byref(name_size),
            domain_buffer,
            ctypes.byref(domain_size),
            ctypes.byref(sid_name_use),
        ):
            return None
        if domain_buffer.value:
            return "{}\\{}".format(domain_buffer.value, name_buffer.value)
        return name_buffer.value
    finally:
        LocalFree(sid_ptr)


def _access_mask_to_permissions(access_mask: int) -> List[str]:
    names = [item["name"] for item in ETW_PERMISSION_DEFINITIONS if access_mask & item["value"]]
    return names or ["UNKNOWN(0x{:08X})".format(access_mask)]


def _convert_sd_to_sddl(security_descriptor: bytes) -> Optional[str]:
    if not is_windows():
        return None
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ConvertSecurityDescriptorToStringSecurityDescriptorW = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
    ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    LocalFree = kernel32.LocalFree
    LocalFree.argtypes = [wintypes.HLOCAL]
    LocalFree.restype = wintypes.HLOCAL

    string_ptr = wintypes.LPWSTR()
    string_len = wintypes.DWORD(0)
    buffer = ctypes.create_string_buffer(security_descriptor)
    success = ConvertSecurityDescriptorToStringSecurityDescriptorW(
        buffer,
        SDDL_REVISION_1,
        DACL_SECURITY_INFORMATION,
        ctypes.byref(string_ptr),
        ctypes.byref(string_len),
    )
    if not success:
        return None
    try:
        return ctypes.wstring_at(string_ptr, string_len.value)
    finally:
        LocalFree(string_ptr)


def _parse_access_mask(rights: str) -> int:
    rights = rights.strip()
    if not rights:
        return 0
    if rights.startswith("0x"):
        return int(rights, 16)
    if rights.isdigit():
        return int(rights, 10)
    mask = 0
    for token in re.findall(r"..", rights):
        if token in _PERMISSION_LOOKUP:
            mask |= _PERMISSION_LOOKUP[token]["value"]
    return mask


def _extract_aces_from_sddl(sddl: Optional[str]) -> List[Dict[str, object]]:
    if not sddl or "D:" not in sddl:
        return []
    dacl = sddl.split("D:", 1)[1]
    if "S:" in dacl:
        dacl = dacl.split("S:", 1)[0]

    aces = []
    for ace_match in re.findall(r"\((.*?)\)", dacl):
        parts = ace_match.split(";")
        if len(parts) != 6:
            continue
        ace_type, ace_flags, rights, object_guid, inherit_guid, sid = parts
        access_mask = _parse_access_mask(rights)
        aces.append(
            {
                "type": {"A": "Allow", "D": "Deny"}.get(ace_type, ace_type),
                "flags": ace_flags,
                "sid": sid,
                "account": _lookup_account_name_from_sid_string(sid) or _SID_ALIAS_MAP.get(sid, sid),
                "access_mask": access_mask,
                "access_mask_hex": "0x{:08X}".format(access_mask),
                "permissions": _access_mask_to_permissions(access_mask),
                "object_guid": object_guid or None,
                "inherit_object_guid": inherit_guid or None,
            }
        )
    return aces


def _load_registered_security_descriptors() -> Dict[str, bytes]:
    if not is_windows() or winreg is None:
        return {}
    descriptors = {}
    for value_name, value_data, _ in _iter_registry_values(winreg.HKEY_LOCAL_MACHINE, _WMI_SECURITY_PATH) or []:
        if _GUID_RE.match(value_name) and isinstance(value_data, (bytes, bytearray)):
            descriptors[_normalize_guid(value_name)] = bytes(value_data)
    return descriptors


def _default_aces() -> List[Dict[str, object]]:
    aces = []
    for ace in DEFAULT_PROVIDER_ACES:
        aces.append(
            {
                "type": ace["type"],
                "sid": ace["sid"],
                "account": ace["account"],
                "access_mask": ace["access_mask"],
                "access_mask_hex": "0x{:08X}".format(ace["access_mask"]),
                "permissions": _access_mask_to_permissions(ace["access_mask"]),
                "flags": "",
                "object_guid": None,
                "inherit_object_guid": None,
            }
        )
    return aces


def _kernel_provider_hint(name: str) -> bool:
    lowered = (name or "").lower()
    return "kernel" in lowered or lowered.startswith("microsoft-windows-kernel")


def _current_user_names() -> List[str]:
    names = []
    username = os.environ.get("USERNAME") or getpass.getuser()
    userdomain = os.environ.get("USERDOMAIN", "")
    if username:
        names.append(username.lower())
    if username and userdomain:
        names.append("{}\\{}".format(userdomain, username).lower())
    return names


def _edit_exposure_principals(aces: List[Dict[str, object]]) -> List[str]:
    current_users = set(_current_user_names())
    principals = []
    for ace in aces:
        if str(ace.get("type", "")).lower() != "allow":
            continue
        account = str(ace.get("account", "")).lower()
        sid = str(ace.get("sid", "")).upper()
        permissions = ace.get("permissions", [])
        if "TRACELOG_GUID_ENABLE" not in permissions:
            continue
        if account == "everyone" or sid == "WD":
            principals.append("Everyone")
            continue
        if account == "authenticated users" or sid == "AU":
            principals.append("Authenticated Users")
            continue
        if account in current_users:
            principals.append("Current User ({})".format(ace.get("account")))
            continue
        if "\\" in account and account.rsplit("\\", 1)[-1] in current_users:
            principals.append("Current User ({})".format(ace.get("account")))
    return list(dict.fromkeys(principals))


def _color_allowed_to_edit(value: bool, colorize: bool) -> str:
    line = "Allowed To Edit: {}".format(str(value).lower())
    if not colorize:
        return line
    color = "31" if value else "32"
    return "\033[1;{}m{}\033[0m".format(color, line)


def enumerate_etw_providers() -> List[Dict[str, object]]:
    if not is_windows():
        raise OSError("ETW provider enumeration is only supported on Windows")

    try:
        providers = _tdh_enumerate_providers()
    except Exception:
        providers = _run_provider_fallback()

    registry_names = _load_registry_name_map()
    security_descriptors = _load_registered_security_descriptors()

    seen = {}
    for provider in providers:
        guid = _normalize_guid(provider.get("guid", ""))
        name = provider.get("name") or registry_names.get(guid, "")
        if guid:
            provider["guid"] = guid
            provider["name"] = name or registry_names.get(guid, guid)
            seen[guid] = provider
        elif name:
            provider["guid"] = ""
            provider["name"] = name

    for guid, name in registry_names.items():
        if guid not in seen:
            seen[guid] = {"guid": guid, "name": name, "schema_source": None, "source": "registry"}

    return [build_provider_report(provider, security_descriptors=security_descriptors) for provider in sorted(seen.values(), key=lambda item: (item.get("name", ""), item.get("guid", "")))]


def build_provider_report(provider: Dict[str, object], security_descriptors: Optional[Dict[str, bytes]] = None) -> Dict[str, object]:
    security_descriptors = security_descriptors or _load_registered_security_descriptors()
    guid = _normalize_guid(provider.get("guid", ""))
    name = provider.get("name") or guid
    registered = guid in security_descriptors
    security_descriptor = security_descriptors.get(guid)
    sddl = _convert_sd_to_sddl(security_descriptor) if security_descriptor else None
    aces = _extract_aces_from_sddl(sddl) if sddl else _default_aces()
    edit_exposure_principals = _edit_exposure_principals(aces)

    return {
        "guid": guid,
        "name": name,
        "source": provider.get("source", "registry"),
        "schema_source": provider.get("schema_source"),
        "security_permissions_registered": registered,
        "security_descriptor_sddl": sddl,
        "permissions": aces,
        "allowed_to_edit_provider": bool(edit_exposure_principals),
        "edit_exposure_principals": edit_exposure_principals,
        "everyone_may_edit_provider": "Everyone" in edit_exposure_principals,
        "kernel_provider_note": _kernel_provider_hint(str(name)),
    }


def search_provider_by_guid(provider_guid: str, providers: Optional[List[Dict[str, object]]] = None) -> Optional[Dict[str, object]]:
    guid = _normalize_guid(provider_guid)
    providers = providers or enumerate_etw_providers()
    for provider in providers:
        if provider.get("guid") == guid:
            return provider
    return None


def search_providers_by_name(name: str, providers: Optional[List[Dict[str, object]]] = None) -> List[Dict[str, object]]:
    providers = providers or enumerate_etw_providers()
    needle = name.lower()
    return [provider for provider in providers if needle in str(provider.get("name", "")).lower()]


def search_providers_by_permission(permission: str, providers: Optional[List[Dict[str, object]]] = None) -> List[Dict[str, object]]:
    providers = providers or enumerate_etw_providers()
    needle = permission.upper()
    matches = []
    for provider in providers:
        for ace in provider.get("permissions", []):
            if needle in (perm.upper() for perm in ace.get("permissions", [])):
                matches.append(provider)
                break
    return matches


def load_provider_requests(path: str) -> List[Dict[str, str]]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("Provider file must contain an array of objects")

    providers = []
    for item in data:
        if not isinstance(item, dict):
            continue
        guid = item.get("providerGuid") or item.get("guid") or ""
        name = item.get("name") or ""
        if not guid and not name:
            continue
        providers.append({"guid": _normalize_guid(guid) if guid else "", "name": name})
    return providers


def build_reports_for_requests(requests: Iterable[Dict[str, str]], providers: Optional[List[Dict[str, object]]] = None) -> List[Dict[str, object]]:
    providers = providers or enumerate_etw_providers()
    by_guid = {provider.get("guid"): provider for provider in providers if provider.get("guid")}
    reports = []
    for item in requests:
        guid = _normalize_guid(item.get("guid", "")) if item.get("guid") else ""
        if guid and guid in by_guid:
            reports.append(by_guid[guid])
            continue
        if item.get("name"):
            matched = search_providers_by_name(item["name"], providers=providers)
            reports.extend(matched or [build_provider_report(item)])
            continue
        reports.append(build_provider_report(item))
    return reports


def describe_permission_catalog() -> List[Dict[str, object]]:
    return list(ETW_PERMISSION_DEFINITIONS)


def _run_command(command: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, capture_output=True, text=True, check=True, timeout=timeout)
    except subprocess.CalledProcessError as exc:
        stdout = (exc.stdout or "").strip()
        stderr = (exc.stderr or "").strip()
        details = []
        if stdout:
            details.append("stdout: {}".format(stdout))
        if stderr:
            details.append("stderr: {}".format(stderr))
        suffix = " ({})".format(" | ".join(details)) if details else ""
        raise OSError("Command failed: {}{}".format(" ".join(command), suffix)) from exc
    except subprocess.TimeoutExpired as exc:
        raise OSError("Command timed out after {} second(s): {}".format(timeout, " ".join(command))) from exc


def _guid_from_string(value: str) -> GUID:
    guid = GUID()
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    ole32.CLSIDFromString.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(GUID)]
    ole32.CLSIDFromString.restype = wintypes.LONG
    result = ole32.CLSIDFromString(value, ctypes.byref(guid))
    if result != 0:
        raise ValueError("Invalid provider GUID: {}".format(value))
    return guid


def _query_session_handle(session_name: str) -> int:
    properties = EVENT_TRACE_PROPERTIES_WITH_NAME()
    ctypes.memset(ctypes.byref(properties), 0, ctypes.sizeof(properties))
    properties.Properties.Wnode.BufferSize = ctypes.sizeof(properties)
    properties.Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID
    properties.Properties.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
    properties.Properties.LogFileNameOffset = (
        ctypes.sizeof(EVENT_TRACE_PROPERTIES) + ctypes.sizeof(wintypes.WCHAR * 1024)
    )

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.ControlTraceW.argtypes = [
        ctypes.c_ulonglong,
        wintypes.LPCWSTR,
        ctypes.POINTER(EVENT_TRACE_PROPERTIES),
        wintypes.ULONG,
    ]
    advapi32.ControlTraceW.restype = wintypes.ULONG

    result = advapi32.ControlTraceW(
        0,
        session_name,
        ctypes.byref(properties.Properties),
        EVENT_TRACE_CONTROL_QUERY,
    )
    if result != 0:
        raise OSError("ControlTraceW query failed for session '{}' with status {}".format(session_name, result))
    return int(properties.Properties.Wnode.HistoricalContext)


def _resolve_provider_identity(provider: str) -> str:
    if _GUID_RE.match(provider):
        return _normalize_guid(provider)
    matched = search_provider_by_guid(provider)
    if matched and matched.get("guid"):
        return matched["guid"]
    matches = search_providers_by_name(provider)
    if not matches:
        return provider
    exact = [item for item in matches if str(item.get("name", "")).lower() == provider.lower()]
    chosen = exact[0] if exact else matches[0]
    return chosen.get("guid") or chosen.get("name") or provider


def resolve_provider_for_edit(provider: str) -> str:
    if _GUID_RE.match(provider):
        return _normalize_guid(provider)
    matches = search_providers_by_name(provider)
    exact = [item for item in matches if str(item.get("name", "")).lower() == provider.lower()]
    if len(exact) == 1 and exact[0].get("guid"):
        return exact[0]["guid"]
    if len(matches) == 1 and matches[0].get("guid"):
        return matches[0]["guid"]
    if not matches:
        raise ValueError("Provider not found: {}".format(provider))
    raise ValueError("Provider name is ambiguous; use a GUID or an exact provider name: {}".format(provider))


def _extract_provider_identity(provider_entry: str) -> str:
    match = re.search(r"\{[0-9a-fA-F-]{36}\}", provider_entry)
    if match:
        return _normalize_guid(match.group(0))
    value = provider_entry.strip()
    if not value:
        raise ValueError("Empty provider entry")
    candidates = [value]
    for separator in (" (", "\t", "  "):
        if separator in value:
            candidates.append(value.split(separator, 1)[0].strip())
    for candidate in candidates:
        if not candidate:
            continue
        try:
            return resolve_provider_for_edit(candidate)
        except ValueError:
            continue
    raise ValueError("Unable to resolve provider entry: {}".format(provider_entry))


def _finalize_session_provider(provider: Optional[Dict[str, str]], resolve_names: bool = True) -> Optional[Dict[str, str]]:
    if not provider:
        return None
    name = str(provider.get("name", "")).strip()
    guid = str(provider.get("guid", "")).strip()
    raw = str(provider.get("raw", "")).strip()

    if not guid:
        match = re.search(r"\{[0-9a-fA-F-]{36}\}", raw or name)
        if match:
            guid = _normalize_guid(match.group(0))
    elif _GUID_RE.match(guid):
        guid = _normalize_guid(guid)

    if not name:
        if raw and not _GUID_RE.match(raw):
            name = raw

    if resolve_names and name and not guid:
        exact = [item for item in search_providers_by_name(name) if str(item.get("name", "")).lower() == name.lower()]
        if len(exact) == 1 and exact[0].get("guid"):
            guid = str(exact[0]["guid"])

    if not (name or guid or raw):
        return None

    return {
        "name": name,
        "guid": guid,
        "raw": raw or name or guid,
    }


def _parse_session_query_output(session_name: str, output: str, resolve_names: bool = True) -> Dict[str, object]:
    details = {}
    providers = []
    in_provider_block = False
    current_provider = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        lowered = line.lower()
        if not line or line.startswith("-") or lowered.startswith("the command completed successfully"):
            continue
        if lowered in ("provider:", "providers:"):
            finalized = _finalize_session_provider(current_provider, resolve_names=resolve_names)
            if finalized:
                providers.append(finalized)
            current_provider = {"name": "", "guid": "", "raw": ""}
            in_provider_block = True
            continue

        is_indented = raw_line.startswith((" ", "\t"))
        if ":" in line:
            key, value = [part.strip() for part in line.split(":", 1)]
            key_lower = key.lower()
            if in_provider_block:
                if not is_indented and key_lower not in ("provider", "providers"):
                    finalized = _finalize_session_provider(current_provider, resolve_names=resolve_names)
                    if finalized:
                        providers.append(finalized)
                    current_provider = None
                    in_provider_block = False
                else:
                    if current_provider is None:
                        current_provider = {"name": "", "guid": "", "raw": ""}
                    if key_lower in ("name", "provider name"):
                        current_provider["name"] = value
                        continue
                    if key_lower in ("provider guid", "guid"):
                        current_provider["guid"] = value
                        continue
                    if key_lower in ("provider", "providers"):
                        finalized = _finalize_session_provider(current_provider, resolve_names=resolve_names)
                        if finalized:
                            providers.append(finalized)
                        current_provider = {"name": value, "guid": "", "raw": value}
                        in_provider_block = True
                        continue
            details[key] = value
            continue

        if in_provider_block:
            if current_provider is None:
                current_provider = {"name": "", "guid": "", "raw": ""}
            if _GUID_RE.match(line):
                current_provider["guid"] = line
            elif not current_provider.get("name"):
                current_provider["name"] = line
            else:
                current_provider["raw"] = "{} {}".format(current_provider.get("raw", "").strip(), line).strip()

    finalized = _finalize_session_provider(current_provider, resolve_names=resolve_names)
    if finalized:
        providers.append(finalized)

    provider_guid = details.get("Provider Guid") or details.get("Guid") or ""
    provider_name = details.get("Provider Name") or details.get("Name") or ""
    if provider_guid or _GUID_RE.match(provider_name):
        providers.append(
            _finalize_session_provider(
                {
                    "name": "" if _GUID_RE.match(provider_name) else provider_name,
                    "guid": provider_guid or provider_name,
                    "raw": provider_name or provider_guid,
                },
                resolve_names=resolve_names,
            )
        )

    deduped = []
    seen = set()
    for provider in providers:
        if provider is None:
            continue
        key = (provider.get("guid", ""), provider.get("name", ""), provider.get("raw", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(provider)

    return {
        "name": session_name,
        "details": details,
        "providers": deduped,
    }


def _resolve_session_provider_targets(session: Dict[str, object]) -> List[str]:
    provider_targets = []
    for entry in session.get("providers", []):
        try:
            if isinstance(entry, dict):
                if entry.get("guid"):
                    provider_targets.append(str(entry["guid"]))
                    continue
                if entry.get("name"):
                    provider_targets.append(resolve_provider_for_edit(str(entry["name"])))
                    continue
                if entry.get("raw"):
                    provider_targets.append(_extract_provider_identity(str(entry["raw"])))
                    continue
            provider_targets.append(_extract_provider_identity(str(entry)))
        except ValueError:
            continue
    return list(dict.fromkeys([item for item in provider_targets if item]))


def edit_session_providers(
    session_name: str,
    enable: bool,
    provider: Optional[str] = None,
    level: int = TRACE_LEVEL_VERBOSE,
    keywords: int = 0xFFFFFFFFFFFFFFFF,
    match_all_keywords: int = 0,
) -> Dict[str, object]:
    if not is_windows():
        raise OSError("ETW session editing is only supported on Windows")

    if enable and not provider:
        raise ValueError("--provider is required when enabling a provider")

    session_handle = _query_session_handle(session_name)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.EnableTraceEx2.argtypes = [
        ctypes.c_ulonglong,
        ctypes.POINTER(GUID),
        wintypes.ULONG,
        ctypes.c_ubyte,
        ctypes.c_ulonglong,
        ctypes.c_ulonglong,
        wintypes.ULONG,
        ctypes.c_void_p,
    ]
    advapi32.EnableTraceEx2.restype = wintypes.ULONG

    control_code = EVENT_CONTROL_CODE_ENABLE_PROVIDER if enable else EVENT_CONTROL_CODE_DISABLE_PROVIDER

    def apply_provider(target: str) -> None:
        target_guid = _guid_from_string(target)
        result = advapi32.EnableTraceEx2(
            session_handle,
            ctypes.byref(target_guid),
            control_code,
            level,
            keywords,
            match_all_keywords,
            0,
            None,
        )
        if result != 0:
            raise OSError(
                "EnableTraceEx2 failed for session '{}' provider '{}' with status {}".format(
                    session_name,
                    target,
                    result,
                )
            )

    if provider:
        provider_targets = [resolve_provider_for_edit(provider)]
        applied = []
        for target in provider_targets:
            apply_provider(target)
            applied.append(target)
        return {
            "session": session_name,
            "action": "enable" if enable else "disable",
            "providers": applied,
        }

    if enable:
        raise ValueError("--provider is required when enabling a provider")

    applied = []
    seen_targets = set()
    message = ""
    for _ in range(256):
        session = list_session_providers(session_name)
        provider_targets = _resolve_session_provider_targets(session)
        if not provider_targets:
            message = "No providers were parsed from the session." if not applied else "No additional providers were parsed from the session."
            break

        repeated = [target for target in provider_targets if target in seen_targets]
        if repeated:
            message = "Session still reports provider(s) after disable; stopping to avoid a repeat loop: {}".format(
                ", ".join(repeated)
            )
            break

        for target in provider_targets:
            apply_provider(target)
            applied.append(target)
            seen_targets.add(target)
        time.sleep(0.1)

    if not applied:
        return {
            "session": session_name,
            "action": "disable",
            "providers": [],
            "message": "{} Nothing was disabled. Pass --provider to disable a specific provider.".format(message).strip(),
        }

    return {
        "session": session_name,
        "action": "disable",
        "providers": applied,
        "message": message,
    }


def capture_provider_events(
    provider: str,
    duration: float = 10.0,
    level: str = "0xFF",
    keywords: str = "0xFFFFFFFFFFFFFFFF",
    keep_files: bool = False,
) -> Dict[str, object]:
    if not is_windows():
        raise OSError("ETW monitoring is only supported on Windows")
    if duration <= 0:
        raise ValueError("duration must be greater than 0")

    provider_identity = _resolve_provider_identity(provider)
    session_name = "taser-etw-{}".format(uuid.uuid4().hex[:8])
    temp_dir = tempfile.mkdtemp(prefix="taser-etw-")
    etl_path = os.path.join(temp_dir, "{}.etl".format(session_name))
    csv_path = os.path.join(temp_dir, "{}.csv".format(session_name))

    create_cmd = [
        "logman",
        "create",
        "trace",
        session_name,
        "-o",
        etl_path,
        "-p",
        provider_identity,
        keywords,
        level,
        "-ets",
    ]
    stop_cmd = ["logman", "stop", session_name, "-ets"]
    tracerpt_cmd = ["tracerpt", etl_path, "-of", "CSV", "-o", csv_path]

    try:
        _run_command(create_cmd)
        time.sleep(duration)
    finally:
        try:
            _run_command(stop_cmd)
        except Exception:
            pass

    _run_command(tracerpt_cmd)

    with open(csv_path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))

    result = {
        "provider": provider,
        "provider_identity": provider_identity,
        "duration": duration,
        "session_name": session_name,
        "etl_path": etl_path if keep_files else "",
        "csv_path": csv_path if keep_files else "",
        "events": rows,
    }

    if not keep_files:
        for path in (etl_path, csv_path):
            try:
                os.remove(path)
            except OSError:
                pass
        try:
            os.rmdir(temp_dir)
        except OSError:
            pass
    else:
        result["temp_dir"] = temp_dir

    return result


def render_event_rows(rows: List[Dict[str, object]], limit: int = 0) -> str:
    if not rows:
        return "No events captured.\n"
    display_rows = rows[:limit] if limit else rows
    preferred_columns = [
        "EventName",
        "Type",
        "Event ID",
        "Level",
        "Task",
        "Opcode",
        "Guid",
        "Provider Name",
        "Process ID",
        "Thread ID",
        "TimeStamp",
    ]
    lines = []
    for index, row in enumerate(display_rows, start=1):
        lines.append("Event #{}".format(index))
        for column in preferred_columns:
            if row.get(column):
                lines.append("  {}: {}".format(column, row[column]))
        for key, value in row.items():
            if key in preferred_columns or value in ("", None):
                continue
            lines.append("  {}: {}".format(key, value))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def list_trace_sessions() -> List[Dict[str, object]]:
    if not is_windows():
        raise OSError("ETW session enumeration is only supported on Windows")

    completed = _run_command(["logman", "query", "-ets"])
    lines = completed.stdout.splitlines()
    sessions = []
    current = None
    table_mode = False

    for raw_line in lines:
        line = raw_line.strip()
        lowered = line.lower()
        if not line or line.startswith("-") or lowered.startswith("the command completed successfully"):
            continue
        if lowered.startswith("data collector set"):
            table_mode = True
            continue
        if table_mode:
            parts = re.split(r"\s{2,}", line)
            if len(parts) >= 3:
                sessions.append(
                    {
                        "name": parts[0],
                        "details": {
                            "Type": parts[1],
                            "Status": parts[2],
                        },
                    }
                )
            elif len(parts) == 1 and parts[0]:
                sessions.append({"name": parts[0], "details": {}})
            continue
        if raw_line and not raw_line.startswith((" ", "\t")):
            if current:
                sessions.append(current)
            current = {"name": line, "details": {}}
            continue
        if ":" in line and current is not None:
            key, value = [part.strip() for part in line.split(":", 1)]
            current["details"][key] = value
    if current:
        sessions.append(current)
    return sessions


def render_trace_sessions(sessions: List[Dict[str, object]]) -> str:
    if not sessions:
        return "No active ETW sessions found.\n"
    lines = []
    for session in sessions:
        lines.append("Session: {}".format(session.get("name", "<unknown>")))
        for key, value in session.get("details", {}).items():
            lines.append("  {}: {}".format(key, value))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def list_session_providers(session_name: str) -> Dict[str, object]:
    if not is_windows():
        raise OSError("ETW session inspection is only supported on Windows")

    completed = _run_command(["logman", "query", session_name, "-ets"])
    return _parse_session_query_output(session_name, completed.stdout)


def render_session_providers(session: Dict[str, object]) -> str:
    lines = ["Session: {}".format(session.get("name", "<unknown>"))]
    for key, value in session.get("details", {}).items():
        if key.lower() in ("provider", "providers"):
            continue
        lines.append("  {}: {}".format(key, value))
    lines.append("Providers:")
    providers = session.get("providers", [])
    if not providers:
        lines.append("  <none parsed>")
    else:
        for provider in providers:
            if isinstance(provider, dict):
                lines.append("  Name: {}".format(provider.get("name") or "<unknown>"))
                lines.append("  GUID: {}".format(provider.get("guid") or "<unknown>"))
                if provider.get("raw") and provider.get("raw") not in (
                    provider.get("name"),
                    provider.get("guid"),
                ):
                    lines.append("  Raw: {}".format(provider.get("raw")))
            else:
                lines.append("  {}".format(provider))
    return "\n".join(lines) + "\n"


def render_text_report(providers: List[Dict[str, object]], show_sddl: bool = False, colorize: bool = False) -> str:
    lines = []
    for provider in providers:
        lines.append("GUID: {}".format(provider.get("guid") or "<unresolved>"))
        lines.append("Name: {}".format(provider.get("name") or "<unknown>"))
        lines.append(_color_allowed_to_edit(bool(provider.get("allowed_to_edit_provider")), colorize))
        lines.append("Security Permissions Registered: {}".format(str(provider.get("security_permissions_registered")).lower()))
        if provider.get("allowed_to_edit_provider"):
            lines.append("Allowed To Edit Principals: {}".format(", ".join(provider.get("edit_exposure_principals", []))))
        if provider.get("kernel_provider_note"):
            lines.append("Kernel Provider Note: permissions shown reflect the user-mode ETW interface and may not represent driver-enforced access.")
        if show_sddl and provider.get("security_descriptor_sddl"):
            lines.append("SDDL: {}".format(provider["security_descriptor_sddl"]))
        lines.append("Permissions:")
        for ace in provider.get("permissions", []):
            lines.append(
                "  {} - {} ({}): {}".format(
                    ace.get("type"),
                    ace.get("account"),
                    ace.get("access_mask_hex"),
                    ", ".join(ace.get("permissions", [])),
                )
            )
        lines.append("")
    return "\n".join(lines).rstrip() + ("\n" if lines else "")


def write_csv_report(path: str, providers: List[Dict[str, object]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "guid",
                "name",
                "security_permissions_registered",
                "ace_type",
                "account",
                "sid",
                "access_mask_hex",
                "permissions",
                "allowed_to_edit_provider",
                "edit_exposure_principals",
                "everyone_may_edit_provider",
                "source",
                "kernel_provider_note",
            ]
        )
        for provider in providers:
            for ace in provider.get("permissions", []):
                writer.writerow(
                    [
                        provider.get("guid"),
                        provider.get("name"),
                        provider.get("security_permissions_registered"),
                        ace.get("type"),
                        ace.get("account"),
                        ace.get("sid"),
                        ace.get("access_mask_hex"),
                        ";".join(ace.get("permissions", [])),
                        provider.get("allowed_to_edit_provider"),
                        ";".join(provider.get("edit_exposure_principals", [])),
                        provider.get("everyone_may_edit_provider"),
                        provider.get("source"),
                        provider.get("kernel_provider_note"),
                    ]
                )


def write_report(path: str, providers: List[Dict[str, object]], fmt: str = "text", show_sddl: bool = False) -> None:
    fmt = fmt.lower()
    if fmt == "csv":
        write_csv_report(path, providers)
        return
    with open(path, "w", encoding="utf-8") as handle:
        if fmt == "json":
            json.dump(providers, handle, indent=2)
            handle.write("\n")
        else:
            handle.write(render_text_report(providers, show_sddl=show_sddl))

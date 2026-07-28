"""Userland hook triage helpers."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os
import struct
from typing import Dict, List, Optional

from taser.windows.pe import PEFormatError, list_native_exports


TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03
MAX_PATH = 260
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

MEM_COMMIT = 0x1000
IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_DIRECTORY_ENTRY_IMPORT = 1

PAGE_GUARD = 0x100

KNOWN_HOOK_PREFIXES = (
    b"\xE9",  # jmp rel32
    b"\xE8",  # call rel32
    b"\xEB",  # jmp rel8
    b"\xFF\x25",  # jmp [rip+imm32] / [mem]
    b"\x48\xB8",  # mov rax, imm64; usually followed by jmp rax
    b"\x68",  # push imm32; often paired with ret
)

SECURITY_VENDOR_KEYWORDS = {
    "Microsoft Defender": ("defender", "msmpeng", "sense", "wdfilter", "wdav", "mpclient", "microsoft antimalware"),
    "CrowdStrike": ("crowdstrike", "csagent", "falcon", "cshook"),
    "SentinelOne": ("sentinel", "sentinelone", "s1agent"),
    "Sophos": ("sophos", "hitmanpro", "sntpl"),
    "Trend Micro": ("trend", "tmmon", "trendmicro", "deep security"),
    "Symantec": ("symantec", "sep", "ses", "broadcom"),
    "McAfee": ("mcafee", "trellix", "mfetp", "mfe"),
    "Elastic": ("elastic", "endpoint security", "elasticendpoint"),
    "Carbon Black": ("carbon black", "cb defense", "confer", "vmware carbon black"),
    "Palo Alto Cortex": ("cortex", "xdr", "traps", "cyvera"),
    "Bitdefender": ("bitdefender", "bdcore", "bdagent"),
    "ESET": ("eset", "ekrn", "epfw"),
    "Malwarebytes": ("malwarebytes", "mbam"),
    "Avast/AVG": ("avast", "avg", "asw", "avgui"),
    "Kaspersky": ("kaspersky", "avp", "kav"),
}


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * MAX_PATH),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", wintypes.LPVOID),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", wintypes.LPVOID),
    ]


def _kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32FirstW.restype = wintypes.BOOL
    kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32NextW.restype = wintypes.BOOL
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.LPVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    return kernel32


def _require_windows() -> None:
    if os.name != "nt":
        raise OSError("This script is only supported on Windows")


def _process_entry(pid: int) -> Optional[Dict[str, object]]:
    for entry in list_processes():
        if int(entry["pid"]) == int(pid):
            return entry
    return None


def list_processes(name: Optional[str] = None, parent_pid: Optional[int] = None) -> List[Dict[str, object]]:
    kernel32 = _kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return []

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    processes = []
    try:
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return processes
        while True:
            item = {
                    "pid": int(entry.th32ProcessID),
                    "name": entry.szExeFile,
                    "parent_pid": int(entry.th32ParentProcessID),
                    "threads": int(entry.cntThreads),
                }
            if (name is None or entry.szExeFile.lower() == name.lower()) and (
                parent_pid is None or int(entry.th32ParentProcessID) == int(parent_pid)
            ):
                processes.append(item)
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        _close_handle(snapshot)
    return processes


def _open_process(pid: int):
    _require_windows()
    if int(pid) <= 0:
        raise OSError("Invalid PID {}. Use a running user-mode process ID greater than 0.".format(pid))

    process_info = _process_entry(pid)
    if not process_info:
        raise OSError("PID {} is not running".format(pid))

    kernel32 = _kernel32()
    access_masks = (
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        PROCESS_QUERY_LIMITED_INFORMATION,
    )
    last_error = 0
    for access_mask in access_masks:
        ctypes.set_last_error(0)
        handle = kernel32.OpenProcess(access_mask, False, pid)
        if handle:
            return handle
        last_error = ctypes.get_last_error()
    raise OSError(
        "OpenProcess failed for PID {} ({}) with Win32 error {}".format(
            pid,
            process_info["name"],
            last_error,
        )
    )


def _close_handle(handle) -> None:
    if handle:
        _kernel32().CloseHandle(handle)


def list_process_modules(pid: int) -> List[Dict[str, object]]:
    _require_windows()
    kernel32 = _kernel32()
    last_error = 0
    for _ in range(10):
        ctypes.set_last_error(0)
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if snapshot != INVALID_HANDLE_VALUE:
            modules = []
            entry = MODULEENTRY32W()
            entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
            try:
                if not kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
                    last_error = ctypes.get_last_error()
                    if last_error == 18:
                        return modules
                    break
                while True:
                    modules.append(
                        {
                            "name": entry.szModule,
                            "path": entry.szExePath,
                            "base_address": ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value,
                            "size": int(entry.modBaseSize),
                        }
                    )
                    if not kernel32.Module32NextW(snapshot, ctypes.byref(entry)):
                        break
                return modules
            finally:
                _close_handle(snapshot)

        last_error = ctypes.get_last_error()
        if not _process_entry(pid):
            raise OSError("PID {} exited before module enumeration completed".format(pid))
        if last_error not in (5, 24, 299):
            break
        ctypes.WinDLL("kernel32").Sleep(150)

    raise OSError("CreateToolhelp32Snapshot failed for PID {} (Win32 error {})".format(pid, last_error))


def _read_process_memory(handle, address: int, size: int) -> bytes:
    kernel32 = _kernel32()
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)):
        return b""
    return buffer.raw[:bytes_read.value]


def _parse_sections(path: str) -> List[Dict[str, int]]:
    with open(path, "rb") as handle:
        data = handle.read(4096)
        if data[:2] != b"MZ":
            return []
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        handle.seek(pe_offset)
        header = handle.read(24)
        if len(header) < 24 or struct.unpack_from("<I", header, 0)[0] != IMAGE_NT_SIGNATURE:
            return []
        file_header = header[4:24]
        number_of_sections = struct.unpack_from("<H", file_header, 2)[0]
        optional_header_size = struct.unpack_from("<H", file_header, 16)[0]
        optional_header = handle.read(optional_header_size)
        section_data = handle.read(number_of_sections * 40)

    sections = []
    for index in range(number_of_sections):
        offset = index * 40
        name = section_data[offset:offset + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virtual_size = struct.unpack_from("<I", section_data, offset + 8)[0]
        virtual_address = struct.unpack_from("<I", section_data, offset + 12)[0]
        raw_size = struct.unpack_from("<I", section_data, offset + 16)[0]
        raw_pointer = struct.unpack_from("<I", section_data, offset + 20)[0]
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_pointer": raw_pointer,
            }
        )
    return sections


def _rva_to_offset(sections: List[Dict[str, int]], rva: int) -> Optional[int]:
    for section in sections:
        start = section["virtual_address"]
        size = max(section["virtual_size"], section["raw_size"])
        if start <= rva < (start + size):
            return section["raw_pointer"] + (rva - start)
    return None


def _module_exports(path: str) -> List[Dict[str, object]]:
    try:
        return list_native_exports(path)["exports"]
    except (OSError, PEFormatError):
        return []


def classify_security_vendor(*values: Optional[str]) -> Optional[str]:
    haystack = " ".join(value for value in values if value).lower()
    if not haystack:
        return None
    for vendor, keywords in SECURITY_VENDOR_KEYWORDS.items():
        if any(keyword in haystack for keyword in keywords):
            return vendor
    return None


def _looks_inline_hook(data: bytes) -> bool:
    if not data:
        return False
    if any(data.startswith(prefix) for prefix in KNOWN_HOOK_PREFIXES):
        return True
    if len(data) >= 3 and data[:3] == b"\x48\xFF\x25":
        return True
    if len(data) >= 6 and data[:2] == b"\x90\xE9":
        return True
    return False


def scan_inline_hooks(pid: int, module_name: Optional[str] = None, max_functions: int = 250) -> List[Dict[str, object]]:
    handle = _open_process(pid)
    try:
        findings = []
        modules = list_process_modules(pid)
        for module in modules:
            if module_name and module_name.lower() not in module["name"].lower():
                continue
            exports = _module_exports(module["path"])
            if not exports:
                continue
            for export in exports[:max_functions]:
                if not export["name"] or not export["rva"]:
                    continue
                address = module["base_address"] + export["rva"]
                live_bytes = _read_process_memory(handle, address, 16)
                if not _looks_inline_hook(live_bytes):
                    continue
                findings.append(
                    {
                        "type": "inline",
                        "pid": pid,
                        "module": module["name"],
                        "module_path": module["path"],
                        "associated_vendor": classify_security_vendor(module["name"], module["path"]),
                        "function": export["name"],
                        "ordinal": export["ordinal"],
                        "address": "0x{:X}".format(address),
                        "bytes": live_bytes.hex(),
                        "reason": "Suspicious control-transfer bytes at function prologue",
                    }
                )
        return findings
    finally:
        _close_handle(handle)


def _read_local_pe_imports(module_path: str) -> List[Dict[str, object]]:
    with open(module_path, "rb") as handle:
        data = handle.read()

    if data[:2] != b"MZ":
        return []
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if struct.unpack_from("<I", data, pe_offset)[0] != IMAGE_NT_SIGNATURE:
        return []

    number_of_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    data_directories_offset = optional_offset + (96 if optional_magic == 0x10B else 112)
    import_rva = struct.unpack_from("<I", data, data_directories_offset + (IMAGE_DIRECTORY_ENTRY_IMPORT * 8))[0]
    if not import_rva:
        return []

    sections = _parse_sections(module_path)
    import_offset = _rva_to_offset(sections, import_rva)
    if import_offset is None:
        return []

    thunk_size = 8 if optional_magic == 0x20B else 4
    descriptor_size = 20
    imports = []
    index = 0
    while True:
        desc_offset = import_offset + (index * descriptor_size)
        original_first_thunk = struct.unpack_from("<I", data, desc_offset)[0]
        name_rva = struct.unpack_from("<I", data, desc_offset + 12)[0]
        first_thunk = struct.unpack_from("<I", data, desc_offset + 16)[0]
        if not any((original_first_thunk, name_rva, first_thunk)):
            break
        name_offset = _rva_to_offset(sections, name_rva)
        dll_name = data[name_offset:].split(b"\x00", 1)[0].decode("ascii", errors="replace") if name_offset is not None else ""
        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = _rva_to_offset(sections, thunk_rva)
        slot_index = 0
        while thunk_offset is not None:
            thunk_value = struct.unpack_from("<Q" if thunk_size == 8 else "<I", data, thunk_offset + (slot_index * thunk_size))[0]
            if not thunk_value:
                break
            if optional_magic == 0x20B:
                ordinal_flag = 0x8000000000000000
            else:
                ordinal_flag = 0x80000000
            if thunk_value & ordinal_flag:
                function_name = "ordinal:{}".format(thunk_value & 0xFFFF)
            else:
                import_name_offset = _rva_to_offset(sections, thunk_value)
                if import_name_offset is None:
                    function_name = ""
                else:
                    function_name = data[import_name_offset + 2:].split(b"\x00", 1)[0].decode("ascii", errors="replace")
            imports.append(
                {
                    "dll": dll_name,
                    "function": function_name,
                    "iat_rva": first_thunk + (slot_index * thunk_size),
                    "thunk_size": thunk_size,
                }
            )
            slot_index += 1
        index += 1
    return imports


def scan_iat_hooks(pid: int, module_name: Optional[str] = None, max_entries: int = 1000) -> List[Dict[str, object]]:
    handle = _open_process(pid)
    try:
        modules = list_process_modules(pid)
        ranges = []
        for module in modules:
            ranges.append((module["base_address"], module["base_address"] + module["size"], module["name"], module["path"]))

        findings = []
        for module in modules:
            if module_name and module_name.lower() not in module["name"].lower():
                continue
            try:
                imports = _read_local_pe_imports(module["path"])
            except OSError:
                continue
            for entry in imports[:max_entries]:
                address = module["base_address"] + entry["iat_rva"]
                data = _read_process_memory(handle, address, entry["thunk_size"])
                if len(data) != entry["thunk_size"]:
                    continue
                target = struct.unpack("<Q" if entry["thunk_size"] == 8 else "<I", data)[0]
                owner = None
                for start, end, owner_name, owner_path in ranges:
                    if start <= target < end:
                        owner = (owner_name, owner_path, start, end)
                        break
                expected_dll = entry["dll"].lower()
                if owner and expected_dll in owner[0].lower():
                    continue
                findings.append(
                    {
                        "type": "iat",
                        "pid": pid,
                        "module": module["name"],
                        "module_path": module["path"],
                        "import_dll": entry["dll"],
                        "function": entry["function"],
                        "iat_address": "0x{:X}".format(address),
                        "target_address": "0x{:X}".format(target),
                        "target_module": owner[0] if owner else "<unknown>",
                        "target_module_path": owner[1] if owner else "",
                        "associated_vendor": classify_security_vendor(
                            owner[0] if owner else "",
                            owner[1] if owner else "",
                            module["name"],
                            module["path"],
                        ),
                        "reason": "IAT entry resolves outside expected module range",
                    }
                )
        return findings
    finally:
        _close_handle(handle)


def scan_userland_hooks(pid: int, module_name: Optional[str] = None, include_iat: bool = True, include_inline: bool = True) -> List[Dict[str, object]]:
    findings = []
    if include_inline:
        findings.extend(scan_inline_hooks(pid, module_name=module_name))
    if include_iat:
        findings.extend(scan_iat_hooks(pid, module_name=module_name))
    return findings

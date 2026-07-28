"""Native PE parsing helpers for Windows-focused scripts."""

from __future__ import annotations

import os
import struct
from typing import Dict, List, Optional


IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14


class PEFormatError(ValueError):
    """Raised when parsing an invalid PE file."""


def _read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _parse_sections(data: bytes, pe_offset: int, number_of_sections: int, optional_header_size: int) -> List[Dict[str, int]]:
    section_offset = pe_offset + 24 + optional_header_size
    sections = []
    for index in range(number_of_sections):
        entry_offset = section_offset + (40 * index)
        name = data[entry_offset:entry_offset + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virtual_size = _read_u32(data, entry_offset + 8)
        virtual_address = _read_u32(data, entry_offset + 12)
        raw_size = _read_u32(data, entry_offset + 16)
        raw_pointer = _read_u32(data, entry_offset + 20)
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
        end = start + size
        if start <= rva < end:
            delta = rva - start
            return section["raw_pointer"] + delta
    return None


def _parse_pe(data: bytes) -> Dict[str, object]:
    if data[:2] != b"MZ":
        raise PEFormatError("File is not a PE executable")

    pe_offset = _read_u32(data, 0x3C)
    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise PEFormatError("PE signature not found")

    machine = _read_u16(data, pe_offset + 4)
    number_of_sections = _read_u16(data, pe_offset + 6)
    optional_header_size = _read_u16(data, pe_offset + 20)
    optional_offset = pe_offset + 24
    optional_magic = _read_u16(data, optional_offset)
    if optional_magic not in (0x10B, 0x20B):
        raise PEFormatError("Unsupported PE optional header")

    data_directories_offset = optional_offset + (96 if optional_magic == 0x10B else 112)
    number_of_rva_and_sizes = _read_u32(data, data_directories_offset - 4)
    sections = _parse_sections(data, pe_offset, number_of_sections, optional_header_size)

    directories = []
    for index in range(min(number_of_rva_and_sizes, 16)):
        entry_offset = data_directories_offset + (index * 8)
        directories.append(
            {
                "virtual_address": _read_u32(data, entry_offset),
                "size": _read_u32(data, entry_offset + 4),
            }
        )

    return {
        "machine": machine,
        "is_64bit": optional_magic == 0x20B,
        "sections": sections,
        "directories": directories,
    }


def get_pe_metadata(path: str) -> Dict[str, object]:
    with open(path, "rb") as handle:
        data = handle.read()

    pe = _parse_pe(data)
    directories = pe["directories"]
    com_descriptor = directories[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR] if len(directories) > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR else {"virtual_address": 0, "size": 0}
    return {
        "path": os.path.abspath(path),
        "machine": pe["machine"],
        "is_64bit": pe["is_64bit"],
        "is_msil": bool(com_descriptor["virtual_address"]),
        "sections": pe["sections"],
        "directories": directories,
    }


def list_native_exports(path: str) -> Dict[str, object]:
    with open(path, "rb") as handle:
        data = handle.read()

    pe = _parse_pe(data)
    directories = pe["directories"]
    export_directory = directories[IMAGE_DIRECTORY_ENTRY_EXPORT] if directories else {"virtual_address": 0, "size": 0}
    com_descriptor = directories[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR] if len(directories) > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR else {"virtual_address": 0, "size": 0}

    metadata = {
        "path": os.path.abspath(path),
        "machine": pe["machine"],
        "is_64bit": pe["is_64bit"],
        "is_msil": bool(com_descriptor["virtual_address"]),
        "exports": [],
    }

    if metadata["is_msil"]:
        return metadata

    if not export_directory["virtual_address"]:
        return metadata

    export_offset = _rva_to_offset(pe["sections"], export_directory["virtual_address"])
    if export_offset is None:
        return metadata

    number_of_functions = _read_u32(data, export_offset + 20)
    number_of_names = _read_u32(data, export_offset + 24)
    address_of_functions = _read_u32(data, export_offset + 28)
    address_of_names = _read_u32(data, export_offset + 32)
    address_of_ordinals = _read_u32(data, export_offset + 36)
    ordinal_base = _read_u32(data, export_offset + 16)

    function_table_offset = _rva_to_offset(pe["sections"], address_of_functions)
    names_table_offset = _rva_to_offset(pe["sections"], address_of_names)
    ordinals_table_offset = _rva_to_offset(pe["sections"], address_of_ordinals)

    if None in (function_table_offset, names_table_offset, ordinals_table_offset):
        return metadata

    exports = []
    name_by_index = {}
    for name_index in range(number_of_names):
        name_rva = _read_u32(data, names_table_offset + (name_index * 4))
        name_offset = _rva_to_offset(pe["sections"], name_rva)
        if name_offset is None:
            continue
        raw_name = data[name_offset:].split(b"\x00", 1)[0]
        function_name = raw_name.decode("ascii", errors="replace")
        ordinal_index = _read_u16(data, ordinals_table_offset + (name_index * 2))
        name_by_index[ordinal_index] = function_name

    for function_index in range(number_of_functions):
        function_rva = _read_u32(data, function_table_offset + (function_index * 4))
        ordinal = ordinal_base + function_index
        exports.append(
            {
                "ordinal": ordinal,
                "rva": function_rva,
                "name": name_by_index.get(function_index, ""),
                "forwarded": export_directory["virtual_address"] <= function_rva < (export_directory["virtual_address"] + export_directory["size"]),
            }
        )

    metadata["exports"] = exports
    return metadata

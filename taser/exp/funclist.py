#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# List exported functions from native PE binaries and identify managed assemblies.

from __future__ import annotations

import argparse
import csv
import json
import sys

from taser import BANNER
from taser.windows.pe import PEFormatError, list_native_exports


def build_parser():
    parser = argparse.ArgumentParser(
        description="\t\t{}".format(sys.argv[0]),
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS,
    )
    parser.add_argument("path", help="Path to a PE executable or DLL")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("-o", "--outfile", help="Optional output file (.json or .csv preferred)")
    parser.add_argument("--named-only", action="store_true", help="Only show exports with names")
    return parser


def render_text(report, named_only=False):
    lines = [
        "Path: {}".format(report["path"]),
        "Architecture: {}".format("x64" if report["is_64bit"] else "x86"),
        "Managed/MSIL: {}".format(str(report["is_msil"]).lower()),
    ]
    if report["is_msil"]:
        lines.append("This binary has a CLR header; use a managed assembly inspector/decompiler workflow instead of native export listing.")
        return "\n".join(lines) + "\n"

    exports = [item for item in report["exports"] if item["name"] or not named_only]
    lines.append("Exports: {}".format(len(exports)))
    for item in exports:
        lines.append(
            "  Ordinal {:>4}  RVA 0x{:08X}  {:<8} {}".format(
                item["ordinal"],
                item["rva"],
                "forward" if item["forwarded"] else "native",
                item["name"] or "<ordinal-only>",
            )
        )
    return "\n".join(lines) + "\n"


def write_csv(path, report, named_only=False):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["path", "is_64bit", "is_msil", "ordinal", "rva", "forwarded", "name"])
        for item in report["exports"]:
            if named_only and not item["name"]:
                continue
            writer.writerow([report["path"], report["is_64bit"], report["is_msil"], item["ordinal"], "0x{:08X}".format(item["rva"]), item["forwarded"], item["name"]])


def cli(argv=None):
    args = build_parser().parse_args(argv)
    sys.stdout.write(BANNER)
    try:
        report = list_native_exports(args.path)
    except (OSError, PEFormatError) as exc:
        raise SystemExit(str(exc))

    if args.outfile:
        if args.outfile.lower().endswith(".csv"):
            write_csv(args.outfile, report, named_only=args.named_only)
        else:
            with open(args.outfile, "w", encoding="utf-8") as handle:
                if args.json or args.outfile.lower().endswith(".json"):
                    json.dump(report, handle, indent=2)
                    handle.write("\n")
                else:
                    handle.write(render_text(report, named_only=args.named_only))

    if args.json:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        sys.stdout.write(render_text(report, named_only=args.named_only))


if __name__ == "__main__":
    cli()

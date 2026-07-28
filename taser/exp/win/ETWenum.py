#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Enumerate ETW providers, resolve security descriptors, and search ETW permissions.

from __future__ import annotations

import argparse
import json
import os
import sys

from taser import BANNER
from taser.windows.etw import (
    describe_permission_catalog,
    enumerate_etw_providers,
    load_provider_requests,
    render_text_report,
    search_provider_by_guid,
    search_providers_by_name,
    search_providers_by_permission,
    write_csv_report,
    write_report,
)


def build_parser():
    parser = argparse.ArgumentParser(
        description="\t\t{}".format(sys.argv[0]),
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS,
    )
    parser.add_argument("--show-sddl", action="store_true", help="Include raw SDDL when available")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    parser.add_argument("--csv", action="store_true", help="Print CSV-oriented output to file when used with -o")
    parser.add_argument("-o", "--outfile", help="Write report to file (.txt, .json, .csv inferred when possible)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="Display all registered ETW providers")

    guid_parser = subparsers.add_parser("search-guid", help="Search for a provider by GUID")
    guid_parser.add_argument("guid", help='Provider GUID, e.g. "{751ef305-6c6e-4fed-b847-02ef79d26aef}"')

    name_parser = subparsers.add_parser("search-name", help="Search for providers by partial name")
    name_parser.add_argument("name", help="Case-insensitive partial provider name")

    permission_parser = subparsers.add_parser("search-permission", help="Search for providers by permission")
    permission_parser.add_argument("permission", help="Permission name, e.g. WMIGUID_QUERY")

    file_parser = subparsers.add_parser("load-file", help="Load providers from a JSON file")
    file_parser.add_argument("path", help="JSON file containing providerGuid/name objects")

    subparsers.add_parser("permissions", help="Display ETW permission definitions")
    return parser


def infer_output_format(args) -> str:
    if args.csv:
        return "csv"
    if args.json:
        return "json"
    if args.outfile:
        ext = os.path.splitext(args.outfile)[1].lower()
        if ext == ".csv":
            return "csv"
        if ext == ".json":
            return "json"
    return "text"


def render_permissions_table() -> str:
    rows = describe_permission_catalog()
    lines = ["Permission\tValue\tDescription"]
    for row in rows:
        lines.append("{}\t0x{:08X}\t{}".format(row["name"], row["value"], row["description"]))
    return "\n".join(lines) + "\n"


def resolve_reports(args):
    providers = enumerate_etw_providers()
    if args.command == "list":
        return providers
    if args.command == "search-guid":
        provider = search_provider_by_guid(args.guid, providers=providers)
        return [provider] if provider else []
    if args.command == "search-name":
        return search_providers_by_name(args.name, providers=providers)
    if args.command == "search-permission":
        return search_providers_by_permission(args.permission, providers=providers)
    if args.command == "load-file":
        requests = load_provider_requests(args.path)
        reports = []
        for item in requests:
            if item.get("guid"):
                provider = search_provider_by_guid(item["guid"], providers=providers)
                if provider:
                    reports.append(provider)
                    continue
            if item.get("name"):
                reports.extend(search_providers_by_name(item["name"], providers=providers))
        return reports
    return []


def output_reports(args, reports):
    fmt = infer_output_format(args)
    if args.outfile:
        write_report(args.outfile, reports, fmt=fmt, show_sddl=args.show_sddl)

    if fmt == "json":
        sys.stdout.write(json.dumps(reports, indent=2) + "\n")
    else:
        sys.stdout.write(render_text_report(reports, show_sddl=args.show_sddl))


def cli(argv=None):
    args = build_parser().parse_args(argv)
    sys.stdout.write(BANNER)

    if args.command == "permissions":
        output = render_permissions_table()
        if args.outfile:
            with open(args.outfile, "w", encoding="utf-8") as handle:
                handle.write(output)
        sys.stdout.write(output)
        return

    reports = resolve_reports(args)
    output_reports(args, reports)


if __name__ == "__main__":
    cli()

#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Enumerate ETW providers, resolve permissions, and search provider metadata.

from __future__ import annotations

import argparse
import json
import os
import sys

from taser import BANNER
from taser.windows.hooks import list_processes
from taser.windows.etw import (
    capture_provider_events,
    describe_permission_catalog,
    edit_session_providers,
    enumerate_etw_providers,
    list_trace_sessions,
    list_session_providers,
    load_provider_requests,
    render_event_rows,
    render_session_providers,
    render_trace_sessions,
    render_text_report,
    search_provider_by_guid,
    search_providers_by_name,
    search_providers_by_permission,
    write_report,
)


def build_parser():
    parser = argparse.ArgumentParser(
        description="\t\t{}".format(sys.argv[0]),
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS,
    )
    parser.add_argument("--show-sddl", action="store_true", help="Include raw SDDL when available")
    parser.add_argument("--json", action="store_true", help="Emit JSON to stdout")
    parser.add_argument("--csv", action="store_true", help="Write CSV when used with -o")
    parser.add_argument("-o", "--outfile", help="Write report to file (.txt, .json, .csv inferred when possible)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="Display all ETW providers with GUIDs and permissions")

    guid_parser = subparsers.add_parser("search-guid", help="Search for a provider by GUID")
    guid_parser.add_argument("guid", help='Provider GUID, e.g. "{751ef305-6c6e-4fed-b847-02ef79d26aef}"')

    name_parser = subparsers.add_parser("search-name", help="Search for providers by partial name")
    name_parser.add_argument("name", help="Case-insensitive partial provider name")

    permission_parser = subparsers.add_parser("search-permission", help="Search for providers by ETW permission")
    permission_parser.add_argument("permission", help="Permission name, e.g. WMIGUID_QUERY")

    file_parser = subparsers.add_parser("load-file", help="Load provider GUID/name requests from a JSON file")
    file_parser.add_argument("path", help="JSON file containing providerGuid/name objects")

    subparsers.add_parser("permissions", help="Display supported ETW permission names and values")
    subparsers.add_parser("list-sessions", help="Display active ETW trace sessions")

    proc_parser = subparsers.add_parser("list-proc", help="List running Windows processes")
    proc_parser.add_argument("--name", help="Filter to process names containing this value")
    proc_parser.add_argument("--pid", type=int, help="Filter to a specific PID")

    session_provider_parser = subparsers.add_parser("session-providers", help="Show providers enabled in an ETW trace session")
    session_provider_parser.add_argument("session", help="ETW session name")

    edit_parser = subparsers.add_parser("edit", help="Enable or disable providers for a specific ETW trace session")
    edit_parser.add_argument("--session", required=True, help="ETW session name")
    action_group = edit_parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--enable", action="store_true", help="Enable the provider in the target session")
    action_group.add_argument("--disable", action="store_true", help="Disable the provider in the target session")
    edit_parser.add_argument("--provider", help="Provider GUID or exact name; omit with --disable to disable parsed providers in the session")
    edit_parser.add_argument("--level", default="0xFF", help="ETW level value for --enable (default: 0xFF)")
    edit_parser.add_argument("--keywords", default="0xFFFFFFFFFFFFFFFF", help="MatchAnyKeyword mask for --enable")
    edit_parser.add_argument("--match-all-keywords", default="0x0", help="MatchAllKeyword mask for --enable")

    monitor_parser = subparsers.add_parser("monitor", help="Capture ETW events from a provider for a bounded interval")
    monitor_parser.add_argument("--provider", required=True, help="Provider name or GUID")
    monitor_parser.add_argument("--duration", type=float, default=10.0, help="Seconds to capture before printing events")
    monitor_parser.add_argument("--level", default="0xFF", help="ETW level value passed to logman (default: 0xFF)")
    monitor_parser.add_argument("--keywords", default="0xFFFFFFFFFFFFFFFF", help="Keyword mask passed to logman")
    monitor_parser.add_argument("--limit", type=int, default=0, help="Maximum number of decoded events to print (0 = all)")
    monitor_parser.add_argument("--keep-files", action="store_true", help="Preserve the ETL/CSV artifacts in a temp directory")
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


def render_processes(processes) -> str:
    if not processes:
        return "No matching processes found.\n"
    lines = []
    for process in processes:
        lines.append(
            "PID: {}  Name: {}  ParentPID: {}  Threads: {}".format(
                process.get("pid"),
                process.get("name"),
                process.get("parent_pid"),
                process.get("threads"),
            )
        )
    lines.append("")
    lines.append("Note: ETW provider enablement is trace-session scoped, not inherently process scoped.")
    lines.append("Use `session-providers <session>` to inspect enabled providers, or `monitor --provider ...` and filter events by Process ID.")
    return "\n".join(lines) + "\n"


def parse_int_arg(value: str) -> int:
    return int(str(value), 0)


def render_edit_result(result) -> str:
    lines = [
        "Session: {}".format(result.get("session", "<unknown>")),
        "Action: {}".format(result.get("action", "<unknown>")),
        "Providers:",
    ]
    providers = result.get("providers", [])
    if not providers:
        lines.append("  <none>")
    else:
        for provider in providers:
            lines.append("  {}".format(provider))
    if result.get("message"):
        lines.append(result["message"])
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
        seen = set()
        for item in requests:
            matches = []
            if item.get("guid"):
                provider = search_provider_by_guid(item["guid"], providers=providers)
                if provider:
                    matches = [provider]
            if not matches and item.get("name"):
                matches = search_providers_by_name(item["name"], providers=providers)
            for report in matches:
                key = (report.get("guid"), report.get("name"))
                if key not in seen:
                    seen.add(key)
                    reports.append(report)
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

    if args.command == "monitor":
        capture = capture_provider_events(
            provider=args.provider,
            duration=args.duration,
            level=args.level,
            keywords=args.keywords,
            keep_files=args.keep_files,
        )
        if args.outfile:
            with open(args.outfile, "w", encoding="utf-8") as handle:
                if args.json or args.outfile.lower().endswith(".json"):
                    json.dump(capture, handle, indent=2)
                    handle.write("\n")
                else:
                    handle.write(render_event_rows(capture["events"], limit=args.limit))
        if args.json:
            sys.stdout.write(json.dumps(capture, indent=2) + "\n")
        else:
            sys.stdout.write(
                "Captured {} event(s) from {} over {} second(s).\n".format(
                    len(capture["events"]),
                    capture["provider"],
                    capture["duration"],
                )
            )
            sys.stdout.write(render_event_rows(capture["events"], limit=args.limit))
            if args.keep_files:
                sys.stdout.write("Artifacts preserved in {}\n".format(capture.get("temp_dir", "")))
        return

    if args.command == "edit":
        try:
            result = edit_session_providers(
                session_name=args.session,
                enable=args.enable,
                provider=args.provider,
                level=parse_int_arg(args.level),
                keywords=parse_int_arg(args.keywords),
                match_all_keywords=parse_int_arg(args.match_all_keywords),
            )
        except (OSError, ValueError) as exc:
            sys.stderr.write("Error: {}\n".format(exc))
            raise SystemExit(1)
        if args.outfile:
            with open(args.outfile, "w", encoding="utf-8") as handle:
                if args.json or args.outfile.lower().endswith(".json"):
                    json.dump(result, handle, indent=2)
                    handle.write("\n")
                else:
                    handle.write(render_edit_result(result))
        if args.json:
            sys.stdout.write(json.dumps(result, indent=2) + "\n")
        else:
            sys.stdout.write(render_edit_result(result))
        return

    if args.command == "list-sessions":
        sessions = list_trace_sessions()
        if args.outfile:
            with open(args.outfile, "w", encoding="utf-8") as handle:
                if args.json or args.outfile.lower().endswith(".json"):
                    json.dump(sessions, handle, indent=2)
                    handle.write("\n")
                else:
                    handle.write(render_trace_sessions(sessions))
        if args.json:
            sys.stdout.write(json.dumps(sessions, indent=2) + "\n")
        else:
            sys.stdout.write(render_trace_sessions(sessions))
        return

    if args.command == "list-proc":
        processes = list_processes()
        if args.name:
            needle = args.name.lower()
            processes = [proc for proc in processes if needle in proc.get("name", "").lower()]
        if args.pid is not None:
            processes = [proc for proc in processes if int(proc.get("pid", -1)) == args.pid]
        if args.outfile:
            with open(args.outfile, "w", encoding="utf-8") as handle:
                if args.json or args.outfile.lower().endswith(".json"):
                    json.dump(processes, handle, indent=2)
                    handle.write("\n")
                else:
                    handle.write(render_processes(processes))
        if args.json:
            sys.stdout.write(json.dumps(processes, indent=2) + "\n")
        else:
            sys.stdout.write(render_processes(processes))
        return

    if args.command == "session-providers":
        session = list_session_providers(args.session)
        if args.outfile:
            with open(args.outfile, "w", encoding="utf-8") as handle:
                if args.json or args.outfile.lower().endswith(".json"):
                    json.dump(session, handle, indent=2)
                    handle.write("\n")
                else:
                    handle.write(render_session_providers(session))
        if args.json:
            sys.stdout.write(json.dumps(session, indent=2) + "\n")
        else:
            sys.stdout.write(render_session_providers(session))
        return

    reports = resolve_reports(args)
    output_reports(args, reports)


if __name__ == "__main__":
    cli()

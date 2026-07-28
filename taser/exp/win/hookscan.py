#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Userland hook triage for inline and IAT anomalies in a target process.

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time

from taser import BANNER
from taser.windows.hooks import list_processes, scan_userland_hooks


def build_parser():
    parser = argparse.ArgumentParser(
        description="\t\t{}".format(sys.argv[0]),
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS,
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-p", "--pid", type=int, help="Target process ID")
    target.add_argument("--launch", help="Launch a process and monitor the child PID")
    parser.add_argument("-m", "--module", help="Only inspect modules whose name contains this value")
    parser.add_argument("--inline-only", action="store_true", help="Only scan for inline hooks")
    parser.add_argument("--iat-only", action="store_true", help="Only scan for IAT anomalies")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between scans in launch mode (default: 2.0)")
    parser.add_argument("--duration", type=float, default=0.0, help="Maximum seconds to monitor in launch mode (0 = until process exits)")
    parser.add_argument("--new-only", action="store_true", help="In launch mode, only print findings not seen in previous scans")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("-o", "--outfile", help="Optional report file (.json or .csv preferred)")
    parser.add_argument("launch_args", nargs=argparse.REMAINDER, help='Arguments for --launch. Prefix with "--" to stop hookscan parsing.')
    return parser


def render_text(findings):
    if not findings:
        return "No suspicious hooks identified.\n"
    lines = []
    for item in findings:
        prefix = "[{}]".format(item["type"].upper())
        if item.get("associated_vendor"):
            prefix = "{} [{}]".format(prefix, item["associated_vendor"])
        lines.append("{} {}!{}".format(prefix, item["module"], item["function"]))
        if item["type"] == "inline":
            lines.append("  Address: {}".format(item["address"]))
            lines.append("  Bytes: {}".format(item["bytes"]))
        else:
            lines.append("  IAT Slot: {}".format(item["iat_address"]))
            lines.append("  Target: {} ({})".format(item["target_address"], item["target_module"]))
        lines.append("  Reason: {}".format(item["reason"]))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_csv(path, findings):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["type", "pid", "module", "function", "address", "target_address", "target_module", "associated_vendor", "reason"])
        for item in findings:
            writer.writerow(
                [
                    item.get("type"),
                    item.get("pid"),
                    item.get("module"),
                    item.get("function"),
                    item.get("address", item.get("iat_address", "")),
                    item.get("target_address", ""),
                    item.get("target_module", ""),
                    item.get("associated_vendor", ""),
                    item.get("reason"),
                ]
            )


def collect_findings(pid, args):
    return scan_userland_hooks(
        pid,
        module_name=args.module,
        include_iat=not args.inline_only,
        include_inline=not args.iat_only,
    )


def findings_key(item):
    return (
        item.get("type"),
        item.get("module"),
        item.get("function"),
        item.get("address", item.get("iat_address")),
        item.get("target_address", ""),
    )


def resolve_monitor_pid(current_pid, launched_name, known_pids):
    if current_pid and any(proc["pid"] == current_pid for proc in list_processes()):
        return current_pid
    candidates = [proc for proc in list_processes(name=launched_name) if proc["pid"] not in known_pids]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item["pid"], reverse=True)
    return candidates[0]["pid"]


def run_launch_monitor(args):
    launch_args = list(args.launch_args or [])
    if launch_args and launch_args[0] == "--":
        launch_args = launch_args[1:]

    proc = subprocess.Popen([args.launch] + launch_args)
    launched_name = args.launch.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    current_pid = proc.pid
    known_pids = {proc.pid}
    sys.stdout.write("Monitoring PID {} for process: {}\n".format(proc.pid, args.launch))

    start = time.time()
    all_findings = []
    seen = set()
    pass_count = 0
    all_keys = set()
    last_status = 0.0
    try:
        while True:
            current_pid = resolve_monitor_pid(current_pid, launched_name, known_pids)
            if current_pid is None:
                if proc.poll() is not None:
                    break
                time.sleep(max(args.interval, 0.1))
                continue
            known_pids.add(current_pid)
            pass_count += 1
            try:
                findings = collect_findings(current_pid, args)
            except OSError:
                if proc.poll() is not None and resolve_monitor_pid(None, launched_name, known_pids) is None:
                    break
                time.sleep(max(args.interval, 0.1))
                continue

            if args.new_only:
                new_findings = [item for item in findings if findings_key(item) not in seen]
            else:
                new_findings = findings

            if new_findings:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                sys.stdout.write("[{}] Findings for PID {} (scan #{})\n".format(timestamp, current_pid, pass_count))
                if args.json:
                    sys.stdout.write(json.dumps(new_findings, indent=2) + "\n")
                else:
                    sys.stdout.write(render_text(new_findings))
            elif (time.time() - last_status) >= max(args.interval, 1.0):
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                sys.stdout.write("[{}] Monitoring PID {} (scan #{}) - no suspicious hooks identified.\n".format(timestamp, current_pid, pass_count))
                last_status = time.time()

            for item in findings:
                key = findings_key(item)
                seen.add(key)
                if key not in all_keys:
                    all_keys.add(key)
                    all_findings.append(item)

            if proc.poll() is not None and resolve_monitor_pid(None, launched_name, known_pids) is None:
                break
            if args.duration and (time.time() - start) >= args.duration:
                break
            time.sleep(max(args.interval, 0.1))
    finally:
        if args.duration and (time.time() - start) >= args.duration:
            if current_pid and any(process["pid"] == current_pid for process in list_processes()):
                sys.stdout.write("Monitoring window reached; PID {} is still running.\n".format(current_pid))

    return all_findings


def cli(argv=None):
    args = build_parser().parse_args(argv)
    sys.stdout.write(BANNER)
    findings = run_launch_monitor(args) if args.launch else collect_findings(args.pid, args)

    if args.outfile:
        if args.outfile.lower().endswith(".csv"):
            write_csv(args.outfile, findings)
        else:
            with open(args.outfile, "w", encoding="utf-8") as handle:
                if args.json or args.outfile.lower().endswith(".json"):
                    json.dump(findings, handle, indent=2)
                    handle.write("\n")
                else:
                    handle.write(render_text(findings))

    if args.json:
        sys.stdout.write(json.dumps(findings, indent=2) + "\n")
    else:
        sys.stdout.write(render_text(findings))


if __name__ == "__main__":
    cli()

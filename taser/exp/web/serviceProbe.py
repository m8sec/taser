#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# ServiceProbe takes in list of targets and will probe for HTTP(S) and TCP services.
#
# Usage:
# python3 -m taser.exp.serviceProbe 10.0.0.0/24 -p 22,21,80,443
# python3 -m taser.exp.serviceProbe nmap_scan.xml
# cat hosts.txt | python3 -m taser.exp.serviceProbe

import sys
import argparse
import os
from time import sleep
from ipparser import ipparser
from threading import Thread, active_count

from taser import logx
from taser import BANNER
from taser.tcp import get_banner
from taser.utils import delimiter2list, val2list
from taser.logx import setup_file_logger, setup_cli_logger, setup_debug_logger
from taser.exp._shared import csv_field, do_http_probe, proto_check


def do_banner_grab(target, port, timeout, cli_logger, file_logger):
    banner = get_banner(target, port, timeout=timeout)
    if banner:
        cli_logger.write("{:40} {}".format((target + ":" + str(port)), banner))
        file_logger.info(','.join([
            csv_field(f'{target}:{str(port)}'),
            csv_field('tcp-banner'),
            csv_field(''),
            csv_field(''),
            csv_field(banner),
            csv_field(''),
            csv_field(''),
            csv_field(''),
        ]))
        return True
    return False


def http_launcher(target, port, args, cli_logger, file_logger):
    for proto in args.proto:
        if proto_check(port, proto) and do_http_probe(target, proto, port, args, cli_logger, file_logger):
            return True
    return False


def launcher(target, port, timeout, args, cli_logger, file_logger):
    if args.http_only:
        http_launcher(target, port, args, cli_logger, file_logger)
        return

    if args.tcp_only:
        do_banner_grab(target, port, timeout, cli_logger, file_logger)
        return

    if http_launcher(target, port, args, cli_logger, file_logger):
        return
    do_banner_grab(target, port, timeout, cli_logger, file_logger)


def main(args, cli_logger, file_logger):
    if args.screenshot:
        os.makedirs(args.screenshot, exist_ok=True)

    for host in ipparser(args.target, open_ports=True, exit_on_error=False):
        for port in [host.split(":")[-1]] if ":" in host else args.port:
            try:
                Thread(target=launcher, args=(host.split(':')[0], int(port), args.timeout, args, cli_logger, file_logger), daemon=True).start()
                while active_count() >= args.max_threads:
                    sleep(0.05)
            except Exception as e:
                logx.color('[!] Error ({}:{}) - {}'.format(host, port, str(e)), fg='yellow', style='bold', windows=args.no_color)
            except KeyboardInterrupt:
                cli_logger.warning('Key event detected, closing...')
                raise SystemExit(0)
    while active_count() > 1:
        sleep(0.05)


def build_parser():
    parser = argparse.ArgumentParser(description="\t\t{0}".format(sys.argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    parser.add_argument('-T', dest='max_threads', type=int, default=75, help='Max threads (Default: 75)')
    parser.add_argument('-t', '--timeout', type=int, default=4, help='Connection timeout')
    parser.add_argument('--debug', action='store_true', help="Show all responses")
    parser.add_argument('-p', '--port', default='80,443', type=lambda x: delimiter2list(x), help='Port (80,443)*')
    parser.add_argument('--proto', default='http,https', type=lambda x: delimiter2list(x), help='HTTP Protocol (http,https)*')
    parser.add_argument('--page', type=str, default='/', help='Add page to HTTP (default:/)')
    parser.add_argument('--no-color', action='store_true', help="Dont use ANSI colors")
    parser.add_argument('-bp', '--body-preview', action='store_true', help='Show the first 100 characters of the HTTP response body in CLI/CSV output')

    mode = parser.add_argument_group("Mode Options")
    mode_flags = mode.add_mutually_exclusive_group(required=False)
    mode_flags.add_argument('--http-only', action='store_true', help='HTTP(S) probe only, skip TCP banner grabs')
    mode_flags.add_argument('--tcp-only', dest='tcp_only', action='store_true', help='TCP banner grab only, skip HTTP(S) checks')
    mode_flags.add_argument('--tcp', dest='tcp_only', action='store_true', help='Compatibility alias for --tcp-only')

    parser.add_argument('--proxy', default='', type=lambda x: val2list(x), help='Comma separated or proxy.txt file')
    parser.add_argument('--no-redirect', action='store_true', help="Do not follow HTTP redirects")

    screenshot = parser.add_argument_group("Screenshot Options")
    screenshot.add_argument('--screenshot', nargs='?', const='./screenshots', default=False, help='Save screenshots to folder (default: ./screenshots)')
    screenshot.add_argument('--browser', choices=['chrome', 'firefox'], default='chrome', help='Selenium browser for screenshots')
    screenshot.add_argument('--driver-path', default=False, help='Optional Selenium driver path')
    screenshot.add_argument('--browser-timeout', type=int, default=10, help='Browser connection timeout')
    screenshot.add_argument('--load-time', type=int, default=2, help='Seconds to wait for document readiness')
    screenshot.add_argument('--no-headless', dest='headless', action='store_false', help='Show browser window while taking screenshots')
    screenshot.add_argument('--window-size', default='1366,768', help='Browser window size')
    screenshot.add_argument('--language', default='en-US,en;q=0.9', help='Browser language preference')
    screenshot.add_argument('--page-load-strategy', choices=['normal', 'eager', 'none'], default='normal', help='Selenium page load strategy')

    report = parser.add_argument_group("Output Options")
    report.add_argument('-o', '--outfile', action='store', help='CSV file to log results')
    report.add_argument('--append', action='store_true', help='Append output log file')

    parser.add_argument(dest='target', nargs='*', help='Target Host(s)/CIDR/nmap xml report')
    parser.set_defaults(headless=True)
    return parser


def cli(argv=None):
    args = build_parser().parse_args(argv)
    run(args)


def run(args):
    setup_debug_logger() if args.debug else False
    cli_logger = setup_cli_logger(spacer=[4, 30])
    file_logger = setup_file_logger(args.outfile, mode='a' if args.append else 'w')
    file_logger.info('"URL","Status","Size","Title","Server","Request URL","Screenshot","Body Preview"')
    cli_logger.info(BANNER)
    main(args, cli_logger, file_logger)


if __name__ == '__main__':
    cli()

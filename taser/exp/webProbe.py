#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# WebProbe takes a list of targets and probes HTTP(S) services only.
# Screenshots are optional and are saved to ./screenshots unless a folder is provided.
#
# Usage:
# python3 -m taser.exp.webProbe 10.0.0.0/24 -p 80,443,8080
# python3 -m taser.exp.webProbe hosts.txt --screenshot
# python3 -m taser.exp.webProbe hosts.txt --screenshot shots --browser firefox --no-headless

import argparse
import os
import sys
from time import sleep
from threading import Thread, active_count

from ipparser import ipparser

from taser import BANNER, logx
from taser.logx import setup_cli_logger, setup_debug_logger, setup_file_logger
from taser.utils import delimiter2list, val2list
from taser.exp._shared import do_http_probe, proto_check

def launcher(target, port, args, cli_logger, file_logger):
    for proto in args.proto:
        if proto_check(port, proto) and do_http_probe(target, proto, port, args, cli_logger, file_logger):
            return


def main(args, cli_logger, file_logger):
    if args.screenshot:
        os.makedirs(args.screenshot, exist_ok=True)

    for host in ipparser(args.target, open_ports=True, exit_on_error=False):
        for port in [host.split(":")[-1]] if ":" in host else args.port:
            try:
                Thread(target=launcher, args=(host.split(':')[0], int(port), args, cli_logger, file_logger), daemon=True).start()
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
    parser.add_argument('-T', dest='max_threads', type=int, default=50, help='Max threads (Default: 50)')
    parser.add_argument('-t', '--timeout', type=int, default=4, help='HTTP connection timeout')
    parser.add_argument('--debug', action='store_true', help="Show debug responses")
    parser.add_argument('-p', '--port', default='80,443', type=lambda x: delimiter2list(x), help='Port (80,443)*')
    parser.add_argument('--proto', default='http,https', type=lambda x: delimiter2list(x), help='HTTP protocol (http,https)*')
    parser.add_argument('--page', type=str, default='/', help='Add page to HTTP request (default:/)')
    parser.add_argument('--no-redirect', action='store_true', help="Do not follow HTTP redirects")
    parser.add_argument('--no-color', action='store_true', help="Do not use ANSI colors")
    parser.add_argument('--proxy', default='', type=lambda x: val2list(x), help='Comma separated proxy list or proxy.txt file')

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
    file_logger.info('"URL","Status","Size","Title","Server","Request URL","Screenshot"')
    cli_logger.info(BANNER)
    main(args, cli_logger, file_logger)


if __name__ == '__main__':
    cli()

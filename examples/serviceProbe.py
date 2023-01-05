#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# ServiceProbe takes in list of targets and will probe for HTTP(S) and TCP services.
#
# Usage:
# python3 serviceProbe.py 10.0.0.0/24 -p 22,21,80,443
# python3 serviceProbe.py nmap_scan.xml
# cat hosts.txt | python3 serviceProbe.py
import sys
import logging
import argparse
from time import sleep
from ipparser import ipparser
from taser.version import BANNER
from threading import Thread, active_count

from taser.tcp import get_banner
from taser.utils import delimiter2list, file_exists
from taser.http import web_request, get_statuscode, get_title, extract_header
from taser.logx import setup_file_logger, setup_cli_logger, setup_debug_logger, list_log_handlers


def do_banner_grab(target, port, timeout):
    banner = get_banner(target, port, timeout=timeout)
    if banner:
        cliLogger.write("{:40} {}".format((target + ":" + str(port)), banner))
        fileLogger.info("{:40} {}".format((target + ":" + str(port)), banner))
        return True
    return False


def do_http_req(target, port, timeout, ssl=False):
    schema = "https://" if ssl else "http://"
    t = schema + target + ":" + str(port) + args.page
    resp = web_request(t, timeout=timeout, proxies=args.proxy)
    code = get_statuscode(resp)
    if code != 0:
        title = get_title(resp)
        server = extract_header('Server', resp)
        cliLogger.write("{:40} code: {:<3} | Size: {:<6}\tServer:{:<15}\tTitle:{}".format(t, code, len(resp.text), server, title))
        fileLogger.info("{:40} code: {:<3} | Size: {:<6}\tServer:{:<15}\tTitle:{}".format(t, code, len(resp.text), server, title))
        return True
    return False


def http_launcher(target, port, timeout):
    for x in [True, False]:
        if do_http_req(target, port, timeout, ssl=x):
            return True
    return False


def launcher(target, port, timeout):
    if not args.tcp:
        if http_launcher(target, port, timeout):
            return
    do_banner_grab(target, port, timeout)


def main():
    for host in collect_target_inputs():
        for port in [host.split(":")[-1]] if ":" in host else args.port:
            try:
                Thread(target=launcher, args=(host.split(':')[0], int(port), args.timeout), daemon=True).start()
                while active_count() > args.max_threads:
                    sleep(0.05)
            except KeyboardInterrupt:
                cliLogger.warning('Key event detected, closing...')
                exit(0)
    while active_count() > 1:
        sleep(0.05)


def collect_target_inputs():
    # Accepts inputs from cmd args or stdin
    hosts = []
    if args.target:
        for x in args.target:
            hosts = hosts + ipparser(x.strip(), open_ports=True, exit_on_error=False, debug=args.debug)
    elif sys.stdin:
        for x in sys.stdin:
            x = x.strip()
            if x:
                hosts = hosts + ipparser(x, open_ports=True, exit_on_error=False, debug=False)
    return list(set(hosts))


if __name__ == '__main__':
    args = argparse.ArgumentParser(description="\t\t{0}".format(sys.argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    args.add_argument('-T', dest='max_threads', type=int, default=65, help='Max threads (Default: 65)')
    args.add_argument('-t', '--timeout', type=int, default=4, help='Connection timeout')
    args.add_argument('--debug', action='store_true', help="Show all responses")
    args.add_argument('-p', '--port', default='80,443', type=lambda x: delimiter2list(x), help='Define port (Default 80, 443)')
    args.add_argument('-page', type=str, default='/', help='Add page to http req (default:/)')
    args.add_argument('-tcp', action='store_true', help="TCP banner grab only, skip http/https checks")
    proxy = args.add_mutually_exclusive_group(required=False)
    proxy.add_argument('--proxy', dest='proxy', action='append', default=[], help='Proxy HTTP requests (IP:Port)')
    proxy.add_argument('--proxy-file', dest='proxy', default=False, type=lambda x: file_exists(args, x), help='Load proxies from file for rotation')
    args.add_argument('-o', dest='outfile', action='store', help='Output to filename to log results')
    args.add_argument('--append-output', dest='append', action='store_true', help='Append output file instead of creating new file')
    args.add_argument(dest='target', nargs='*', help='Target Host(s)/CIDR/nmap xml report')
    args = args.parse_args()

    setup_debug_logger() if args.debug else False
    cliLogger = setup_cli_logger(spacer=[4, 30])
    fileLogger = setup_file_logger(args.outfile, mode='a' if args.append else 'w')

    cliLogger.info(BANNER)
    main()

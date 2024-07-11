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
import argparse
from time import sleep
from ipparser import ipparser
from threading import Thread, active_count

from taser import logx
from taser import BANNER
from taser.tcp import get_banner
from taser.utils import delimiter2list, val2list
from taser.http import web_request, get_statuscode, get_title, extract_header
from taser.logx import setup_file_logger, setup_cli_logger, setup_debug_logger


def do_banner_grab(target, port, timeout):
    banner = get_banner(target, port, timeout=timeout)
    if banner:
        cliLogger.write("{:40} {}".format((target + ":" + str(port)), banner))
        fileLogger.info(f'"{target}:{str(port)}","{banner}"')
        return True
    return False


########################
# URL build support
########################
def proto_check(port, proto):
    # Check port 80 always uses http and 443 https
    return not ((port == 443 and proto == 'http') or (port == 80 and proto == 'https'))


def append_port(port, proto):
    # only append non-standard ports to URL
    if (int(port) == 80 and proto == 'http') or (int(port) == 443 and proto == 'https'):
        return ''
    return ':' + str(port)


########################
# Primary HTTP & TCP req
########################
def do_http_req(target, protocol, port, timeout):
    url = f'{protocol}://{target}{append_port(port, protocol)}{args.page}'
    resp = web_request(url, timeout=timeout, proxies=args.proxy)
    code = get_statuscode(resp)

    if code != 0:
        title = get_title(resp)
        server = extract_header('Server', resp)

        # Map http status to color
        color_mapping = {200: 'green', 404: 'red', 500: 'red'}
        tmp_c = color_mapping.get(code, 'yellow')
        c = '{} => {}'.format(resp.history[0].status_code, code) if resp.history else code

        cliLogger.write("{} {} {} {} {}".format(
            resp.url,
            logx.highlight('[{}]'.format(c), fg=tmp_c, style='none', windows=args.no_color),
            logx.highlight('[size: {}]'.format(len(resp.text)), fg='yellow', style='none', windows=args.no_color),
            logx.highlight('[{}]'.format(server), fg='cyan', style='none', windows=args.no_color),
            logx.highlight('[{}]'.format(title), fg='purple', style='none', windows=args.no_color)))

        fileLogger.info(f'"{resp.url}","{resp.status_code}","{len(resp.text)}","{title}","{server}","{resp.request.url}"')
        return True
    return False


def http_launcher(target, port, timeout):
    for proto in args.proto:
        if proto_check(port, proto) and do_http_req(target, proto, port, timeout):
            return True
    return False


def launcher(target, port, timeout):
    if not args.tcp:
        if http_launcher(target, port, timeout):
            return
    do_banner_grab(target, port, timeout)


def main():
    for host in ipparser(args.target, open_ports=True, exit_on_error=False):
        for port in [host.split(":")[-1]] if ":" in host else args.port:
            try:
                Thread(target=launcher, args=(host.split(':')[0], int(port), args.timeout), daemon=True).start()
                while active_count() > args.max_threads:
                    sleep(0.05)
            except Exception as e:
                logx.highlight('[!] Error ({}:{}) - {}'.format(host, port, str(e)), fg='yellow', style='bold', windows=args.no_color)
            except KeyboardInterrupt:
                cliLogger.warning('Key event detected, closing...')
                exit(0)
    while active_count() > 1:
        sleep(0.05)


if __name__ == '__main__':
    args = argparse.ArgumentParser(description="\t\t{0}".format(sys.argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    args.add_argument('-T', dest='max_threads', type=int, default=75, help='Max threads (Default: 75)')
    args.add_argument('-t', '--timeout', type=int, default=4, help='Connection timeout')
    args.add_argument('--debug', action='store_true', help="Show all responses")
    args.add_argument('-p', '--port', default='80,443', type=lambda x: delimiter2list(x), help='Port (80,443)*')
    args.add_argument('--proto', default='http,https', type=lambda x: delimiter2list(x), help='HTTP Protocol (http,https)*')
    args.add_argument('--page', type=str, default='/', help='Add page to HTTP (default:/)')
    args.add_argument('--tcp', action='store_true', help="TCP banner grab only, skip http/https checks")
    args.add_argument('--no-color', action='store_true', help="Dont use ANSI colors")

    proxy = args.add_argument_group("Proxy Options")
    args.add_argument('--proxy', default='', type=lambda x: val2list(x), help='Comma separated or proxy.txt file')

    report = args.add_argument_group("Output Options")
    report.add_argument('-o', '--outfile', action='store', help='CSV file to log results')
    report.add_argument('--append', action='store_true', help='Append output log file')

    args.add_argument(dest='target', nargs='*', help='Target Host(s)/CIDR/nmap xml report')
    args = args.parse_args()

    setup_debug_logger() if args.debug else False
    cliLogger = setup_cli_logger(spacer=[4, 30])
    fileLogger = setup_file_logger(args.outfile, mode='a' if args.append else 'w')
    fileLogger.info('"URL","Status","Size","Title","Server","Request URL"')

    cliLogger.info(BANNER)
    main()

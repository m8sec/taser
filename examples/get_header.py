#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Quickly enumerate HTTP headers and collect site information such as
# response code, page size, title, and HTTP response headers to prioritize
# potential targets.
#
# Usage:
# get_header.py --header Server example.com
# get_header.py -T 35 -o report.txt 192.168.1.0/24
import argparse
from sys import argv
from time import sleep
from random import sample
from ipparser import ipparser
from threading import Thread, active_count

from taser.version import BANNER
from taser.printx import highlight
from taser.utils import file_exists, delimiter2list
from taser.logx import setup_file_logger, setup_cli_logger
from taser.http import extract_header, get_title, get_statuscode, web_request
from taser.http.parser import URLParser

URL = []
DEFAULT = ['host', 'server', 'x-', 'access-', 'allow', 'www-', 'cache', 'origin', 'via', 'link']
BLACKLIST = ['X-XSS-Protection', 'XSS-Protection', 'Strict-Transport-Security', 'X-Content-Type-Options',
             'Accept-Ranges', 'Content-Length', 'Connection', 'Date', 'ETag']


def output_handler(resp, args):
    cliLogger.info([resp.url, highlight('Title', fg='gray'), '\t         ({})\t {}'.format(get_statuscode(resp), get_title(resp))])
    if args.header:
        for x in delimiter2list(args.header, delimiter=","):
            h = extract_header(x, resp)
            if h:
                cliLogger.info([resp.url, x+":", h])
    elif args.verbose:
        for k, v in resp.headers.items():
            if k not in BLACKLIST:
                cliLogger.info([resp.url, k+":", v])
    else:
        for k, v in resp.headers.items():
            for w in DEFAULT:
                if k.lower().startswith(w):
                    cliLogger.info([resp.url, k+":", v])


def launcher(url):
    resp = web_request(url, proxies=args.proxy)
    if get_statuscode(resp) != 0:
        if resp.url not in URL:
            # Add urls to array, prevent duplicates
            URL.append(resp.url)
            output_handler(resp, args)


######################
# Handle Target Inputs
######################
def add_protocol(target, protocols=['https://', 'http://']):
    # Return array of target+protocol, allowing for various user inputs
    return [target] if target.startswith(tuple(protocols)) else [x+"://"+target for x in protocols]


def add_port(target, ports=[80, 443]):
    # Return array of target:port, allowing for various user inputs
    return [target] if ":" in URLParser.extract_subdomain(target) or len(ports) <= 0 else [target+":"+x for x in ports]


def add_page(target, pages=["/"]):
    return [target] if URLParser.extract_page(target) else [URLParser.rm_slash(target)+x for x in pages]


def collect_targets(target_input, protocols=['https', 'http'], ports=[80, 443], pages=["/"]):
    tmp = []
    for x in ipparser(target_input, resolve=args.resolve, open_ports=True, exit_on_error=False, debug=False):
        for y in add_protocol(x, protocols):
            for z in add_port(y, ports):
                for t in add_page(z, pages):
                    tmp.append(t)
    return list(set(tmp))


def main():
    for url in collect_targets(args.target[0], args.protocol, args.port, args.page):
        try:
            Thread(target=launcher, args=(url,), daemon=True).start()
            while active_count() >= args.max_threads:
                sleep(0.05)
        except KeyboardInterrupt:
            cliLogger.warning('Key event detected, closing...', bullet='[!] ', fg='yellow')
            exit(0)
    while active_count() > 1:
        sleep(0.05)


if __name__ == '__main__':
    args = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    args.add_argument('-t', dest='timeout', type=int, default=4, help='Connection timeout')
    args.add_argument('-v', dest="verbose", action='store_true', help='Show full responses')
    args.add_argument('-T', dest='max_threads', type=int, default=45, help='Max threads (Default: 5)')
    args.add_argument('-o', dest='outfile', action='store', help='Filename to write results (optional)')

    args.add_argument('--port', default='', type=lambda x: delimiter2list(x), help="Define target port(s)")
    args.add_argument('--page', default='/', type=lambda x: delimiter2list(x), help="Define request page (default /)")
    args.add_argument('-H', '--header', dest="header", type=str, default=False, help="Extract header(s) from response, i.e: Server,X-Powered-By")

    proxy = args.add_argument_group("Proxy Options")
    p = proxy.add_mutually_exclusive_group(required=False)
    p.add_argument('--proxy', dest='proxy', action='append', default=[], help='Proxy requests (IP:Port)')
    p.add_argument('--proxy-file', dest='proxy', default=False, type=lambda x: file_exists(args, x), help='Load proxies from file')

    args.add_argument('--protocol', default='http,https', type=lambda x: delimiter2list(x), help='Define protocol (Default http,https)')
    args.add_argument('--resolve', action='store_true', help='Resolve all DNS names before enumeration')
    args.add_argument(dest='target', nargs='+', help='Target')
    args = args.parse_args()

    cliLogger = setup_cli_logger(spacer=[4, 45, 30])
    cliLogger.info(BANNER)
    fileLogger = setup_file_logger(args.outfile, mode='w')
    main()

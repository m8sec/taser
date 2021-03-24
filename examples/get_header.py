#!/usr/bin/env python3
# Author: @m8r0wn
#
# Quickly enumerate HTTP headers and collect site information such as
# response code, page size, title, and HTTP response headers to prioritize
# potential targets.
#
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
from taser.logx import setup_fileLogger, setup_consoleLogger
from taser.proto.http import extract_header, get_pagetitle, get_statuscode, web_request, target2url

DEFAULT = ['host', 'server', 'x-', 'access-', 'allow', 'www-', 'cache', 'origin', 'via', 'link']
BLACKLIST = ['X-XSS-Protection','XSS-Protection','Strict-Transport-Security','X-Content-Type-Options',
                'Accept-Ranges','Content-Length','Connection','Date','ETag']

def output_handler(resp, args):
    cliLogger.info([resp.url, highlight('Title',fg='gray'), '\t         ({})\t {}'.format(get_statuscode(resp), get_pagetitle(resp))])
    if args.header:
        for x in delimiter2list(args.header, delimiter=","):
            h = extract_header(x, resp)
            if h:
                cliLogger.info([resp.url, x+":", h])
    elif args.verbose:
        for k,v in resp.headers.items():
            if k not in BLACKLIST:
                cliLogger.info([resp.url, k+":", v])
    else:
        for k, v in resp.headers.items():
            for w in DEFAULT:
                if k.lower().startswith(w):
                    cliLogger.info([resp.url, k+":", v])

def minion(url):
    resp = web_request(url, proxies=args.proxy, debug=args.verbose)
    if get_statuscode(resp) != 0:
        output_handler(resp, args)

def main(args, urls):
    for url in urls:
        try:
            Thread(target=minion, args=(url,), daemon=True).start()
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

    args.add_argument('--port', dest="port", type=int, default=False,help="Define request port")
    args.add_argument('--page', dest="page", type=str, default='/',help="Define request page")
    args.add_argument('-H','--header', dest="header", type=str, default=False, help="Extract header(s) from response, i.e: Server,X-Powered-By")

    proxy = args.add_mutually_exclusive_group(required=False)
    proxy.add_argument('--proxy', dest='proxy', action='append', default=[], help='Proxy requests (IP:Port)')
    proxy.add_argument('--proxy-file', dest='proxy', default=False, type=lambda x: file_exists(args, x), help='Load proxies from file for rotation')

    args.add_argument('--proto', dest="protocol", type=str, default=False,help="Define protocol {http,https}")
    args.add_argument('--resolve', dest='resolve', action='store_true', help='Resolve all DNS names before enumeration')
    args.add_argument(dest='target', nargs='+', help='Target')
    args = args.parse_args()

    cliLogger = setup_consoleLogger(spacers=[45,30,])
    fileLogger = setup_fileLogger(args.outfile, mode='w')
    cliLogger.info(BANNER)

    urls = []
    tmp_ip = ipparser(args.target[0], resolve=args.resolve, open_ports=True, exit_on_error=False, debug=False)
    for x in sample(tmp_ip, len(tmp_ip)):
        proto = [args.protocol] if args.protocol else ['http', 'https']
        for p in proto:
            tmp_x = x[:-1] if x.endswith("/") else x
            tmp_x = tmp_x+":"+str(args.port) if args.port else tmp_x
            u = target2url(tmp_x+args.page, protocol=p)
            urls.append(u) if u not in urls else urls

    main(args, urls)

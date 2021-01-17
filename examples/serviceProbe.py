#!/usr/bin/env python3
# Author: @m8r0wn
#
# ServiceProbe takes in list of targets and will probe for HTTP(S) and TCP services.
#
# serviceProbe.py 10.0.0.0/24 -p 22,21,80,443
# serviceProbe.py nmap_scan.xml
# cat hosts.txt | python3 serviceProbe.py

import sys
import argparse
from time import sleep
from ipparser import ipparser
from taser.version import BANNER
from threading import Thread, active_count

from taser.proto.tcp import get_banner
from taser.utils import delimiter2list, file_exists
from taser.logx import setup_fileLogger, setup_consoleLogger
from taser.proto.http import web_request, get_statuscode, get_pagetitle, extract_header

def tcpBanner(target, port, timeout):
    banner = get_banner(target, int(port), timeout=timeout)
    if banner:
        cliLogger.write("{:40} {}".format((target + ":" + str(port)), banner))
        fileLogger.info("{:40} {}".format((target + ":" + str(port)), banner))
        return True
    return False

def tryHTTP(target, port, timeout, ssl=False, verbose=False, proxies=[]):
    schema = "https://" if ssl else "http://"
    t = schema + target + ":" + str(port)
    resp = web_request(t, timeout=timeout, debug=verbose, proxies=proxies)
    code = get_statuscode(resp)
    if code != 0:
        title = get_pagetitle(resp)
        server = extract_header('Server', resp)
        cliLogger.write("{:40} code: {:<3} | Size: {:<6}\tServer:{:<15}\tTitle:{}".format(t, code, len(resp.text), server, title))
        fileLogger.info("{:40} code: {:<3} | Size: {:<6}\tServer:{:<15}\tTitle:{}".format(t, code, len(resp.text), server, title))
        return True
    return False

def http_launcher(target, port, timeout, verbose):
    for x in [True, False]:
        if tryHTTP(target, port, timeout, ssl=x, verbose=verbose):
            return True
    return False

def getPorts(ports):
    '''Define ports for enumeration'''
    if ports == 'web':
        return [80,443,8080,8443]
    elif ports == 'advweb':
        return [80,443,2301,2381,8080,8081,8082,8443,8834,8843,4567,88]
    else:
        return delimiter2list(ports)

def collect_targets(targets, ports):
    '''Convert all targets to target:port format'''
    tmp = []
    for t in targets:
        if ":" in t:
            tmp.append(t)
        else:
            for p in ports:
                tmp.append("{}:{}".format(t,p))
    return tmp

def launcher(target, port, verbose, timeout):
    if not args.tcp:
        if http_launcher(target, port, timeout, verbose):
            return
    tcpBanner(target, port, timeout)

def main(hosts):
    for target in hosts:
        try:
            if ":" in target:
                target, port = target.split(":")
            Thread(target=launcher, args=(target, int(port), args.verbose, args.timeout,), daemon=True).start()
            while active_count() > args.max_threads:
                sleep(0.05)
        except KeyboardInterrupt:
            cliLogger.warning('[!] Key event detected, closing...')
            exit(0)
    while active_count() > 1:
        sleep(0.05)

if __name__ == '__main__':
    args = argparse.ArgumentParser(description="\t\t{0}".format(sys.argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    args.add_argument('-T', dest='max_threads', type=int, default=75, help='Max threads (Default: 55)')
    args.add_argument('-t', dest='timeout', type=int, default=2, help='Connection timeout')
    args.add_argument('-v', dest="verbose", action='store_true', help="Show all responses")
    args.add_argument('-p', dest='port', type=str, default='80,443', help='Define port (Default 80 & 443)')
    args.add_argument('-tcp', dest="tcp", action='store_true', help="TCP banner grab only, skip http/https checks")

    proxy = args.add_mutually_exclusive_group(required=False)
    proxy.add_argument('--proxy', dest='proxy', action='append', default=[], help='Proxy HTTP requests (IP:Port)')
    proxy.add_argument('--proxy-file', dest='proxy', default=False, type=lambda x: file_exists(args, x), help='Load proxies from file for rotation')

    args.add_argument('-o', dest='outfile', action='store', help='Output to filename to log results')
    args.add_argument('--append-output', dest='append', action='store_true', help='Append output file instead of creating new file')

    args.add_argument(dest='target', nargs='*', help='Target Host(s)/CIDR/nmap xml report')
    args = args.parse_args()

    cliLogger = setup_consoleLogger(spacers=[30])
    fileLogger = setup_fileLogger(args.outfile, mode='a' if args.append else 'w')
    cliLogger.info(BANNER)

    hosts = []
    if args.target:
        for x in args.target:
            hosts = hosts + ipparser(x.strip(), open_ports=True, exit_on_error=False, debug=False)
    elif sys.stdin:
        for x in sys.stdin:
            x = x.strip()
            if x:
                hosts = hosts + ipparser(x, open_ports=True, exit_on_error=False, debug=False)
    set(hosts)

    ports = getPorts(args.port)
    hosts = collect_targets(hosts, ports)

    main(hosts)
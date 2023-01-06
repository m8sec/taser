#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Script to perform DNS brute forcing. Add "FUZZ" keyword
# in target to change standard injection point and aid in additional
# discovery
#
# Usage:
# python3 dns_brute.py test.com -w subdomains.txt
# python3 dns_brute.py admin.FUZZ.test.com -w subdomains.txt
import logging
import argparse
import threading
from os import path
from sys import argv
from time import sleep
import dns.reversename
from ipparser import ipparser
from taser.dns import DNSutils
from taser.version import BANNER
from taser.utils import file_exists, delimiter2list, ranger
from taser.logx import setup_file_logger, setup_cli_logger, setup_debug_logger


def fuzz_finder(target):
    # Validate FUZZ keyword in target input
    return target if "FUZZ" in target else '.'.join(['FUZZ', target])


def payload_parser():
    # Parse payload inputs and passing back to call object
    if args.p_string:
        return args.p_string
    elif args.p_num:
        return args.p_num
    elif args.p_wordlist and path.exists(args.p_wordlist):
        return [line.strip() for line in open(args.p_wordlist)]
    return []


def dns_brute(host, payload):
    target = host.replace('FUZZ', str(payload))
    try:
        addr = target if args.type == 'A' else dns.reversename.from_address(target)
        for x in DNSutils.dns_lookup(addr, args.type, args.nameserver, args.timeout):
            if args.data_only:
                cliLogger.write(x)
                fileLogger.info(x)
            else:
                cliLogger.success("{} - {}".format(target, x))
                fileLogger.info("{},{}".format(target, x))
    except Exception as e:
        logging.debug('{} ({}) - {}'.format(target, args.type, str(e)))


def main():
    payloads = payload_parser()

    for t in ipparser(args.target[0]):
        for p in payloads:
            try:
                threading.Thread(target=dns_brute, args=(fuzz_finder(t), p), daemon=True).start()
                while threading.active_count() >= args.max_threads:
                    sleep(0.05)
            except KeyboardInterrupt:
                cliLogger.warning('Key event detected, closing...', bullet='[!] ', fg='yellow')
                exit(0)
    while threading.active_count() > 1:
        sleep(0.05)


if __name__ == '__main__':
    args = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    args.add_argument('-T', dest='max_threads', type=int, default=10, help='Max threads')
    args.add_argument('-t', dest='timeout', type=int, default=3, help='Connection timeout')

    req = args.add_argument_group(title='DNS Options')
    req.add_argument('--type', choices=['A', 'PTR'], default="A", help="Lookup type [A*, PTR]")
    req.add_argument('-ns', '--nameserver', default='', type=lambda x: delimiter2list(x), help='Define nameserver(s)')

    f = args.add_argument_group(title='Payload Options')
    fuzz = f.add_mutually_exclusive_group(required=True)
    fuzz.add_argument('-w', dest="p_wordlist", default='', type=str, help='Fuzz using wordlist(s)')
    fuzz.add_argument('-s', dest="p_string", type=lambda x: delimiter2list(x), help='Fuzz using string value (single, comma seperated)')
    fuzz.add_argument('-n', dest="p_num", type=lambda x: ranger(x), help='Number value for fuzzing (Single, range, or comma seperated)')

    output = args.add_argument_group(title='Output Options')
    output.add_argument('-o', dest='outfile', type=str, default=False, help='Log output to file')
    output.add_argument('--data-only', action='store_true', help='only print URLS via CLI & file')
    output.add_argument('-v', dest="verbose", action='store_true', help='Show resolve failures')

    args.add_argument(dest='target', nargs='+', help='Target URL [positional]')
    args = args.parse_args()

    cliLogger = setup_cli_logger(spacer=[4])
    cliLogger.info(BANNER)
    fileLogger = setup_file_logger(args.outfile, mode='w')
    setup_debug_logger() if args.verbose else False
    main()

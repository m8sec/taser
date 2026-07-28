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
from taser import BANNER
from ipparser import ipparser
from taser.dns import DNSutils
from taser.utils import delimiter2list, ranger
from taser.logx import setup_file_logger, setup_cli_logger, setup_debug_logger


def fuzz_finder(target):
    # Validate FUZZ keyword in target input
    return target if "FUZZ" in target else '.'.join(['FUZZ', target])


def payload_parser(args):
    # Parse payload inputs and passing back to call object
    if args.p_string:
        return args.p_string
    elif args.p_num:
        return args.p_num
    elif args.p_wordlist and path.exists(args.p_wordlist):
        with open(args.p_wordlist, encoding='utf-8') as handle:
            return [line.strip() for line in handle]
    return []


def dns_brute(host, payload, args, cli_logger, file_logger):
    target = host.replace('FUZZ', str(payload))
    try:
        for x in DNSutils.query(target, args.type, ns=args.nameserver, timeout=args.timeout):
            if args.data_only:
                cli_logger.write(x)
                file_logger.info(x)
            else:
                cli_logger.success("{} - {}".format(target, x))
                file_logger.info("{},{}".format(target, x))
    except Exception as e:
        logging.debug('{} ({}) - {}'.format(target, args.type, str(e)))


def main(args, cli_logger, file_logger):
    payloads = payload_parser(args)

    for t in ipparser(args.target[0]):
        for p in payloads:
            try:
                threading.Thread(target=dns_brute, args=(fuzz_finder(t), p, args, cli_logger, file_logger), daemon=True).start()
                while threading.active_count() >= args.max_threads:
                    sleep(0.05)
            except KeyboardInterrupt:
                cli_logger.warning('Key event detected, closing...', bullet='[!] ', fg='yellow')
                exit(0)
    while threading.active_count() > 1:
        sleep(0.05)


def build_parser():
    parser = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    parser.add_argument('-T', dest='max_threads', type=int, default=10, help='Max threads')
    parser.add_argument('-t', dest='timeout', type=int, default=3, help='Connection timeout')

    req = parser.add_argument_group(title='DNS Options')
    req.add_argument('--type', choices=['A'], default="A", help=argparse.SUPPRESS)
    req.add_argument('-ns', '--nameserver', default='', type=lambda x: delimiter2list(x), help='Define nameserver(s)')

    f = parser.add_argument_group(title='Payload Options')
    fuzz = f.add_mutually_exclusive_group(required=True)
    fuzz.add_argument('-w', dest="p_wordlist", default='', type=str, help='Fuzz using wordlist(s)')
    fuzz.add_argument('-s', dest="p_string", type=lambda x: delimiter2list(x), help='Fuzz using string value (single, comma seperated)')
    fuzz.add_argument('-n', dest="p_num", type=lambda x: ranger(x), help='Number value for fuzzing (Single, range, or comma seperated)')

    output = parser.add_argument_group(title='Output Options')
    output.add_argument('-o', dest='outfile', type=str, default=False, help='Log output to file')
    output.add_argument('--data-only', action='store_true', help='only print URLS via CLI & file')
    output.add_argument('--debug', action='store_true', help='Show resolve failures')

    parser.add_argument(dest='target', nargs='+', help='Target URL [positional]')
    return parser


def cli(argv=None):
    args = build_parser().parse_args(argv)

    cli_logger = setup_cli_logger(spacer=[4])
    cli_logger.info(BANNER)
    file_logger = setup_file_logger(args.outfile, mode='w')
    setup_debug_logger() if args.debug else False
    main(args, cli_logger, file_logger)


if __name__ == '__main__':
    cli()

#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Perform various DNS lookups and test zone transfers
#
# Usage:
# python3 dnslookup.py -t A HostFile.txt
# python3 dnslookup.py -r 8.8.8.8
import logging
import argparse
from sys import exit, argv
from ipparser import ipparser
from taser.dns import DNSutils
from taser.version import BANNER
from taser.utils import delimiter2list
from taser.logx import setup_file_logger, setup_cli_logger, setup_debug_logger, TaserAdapter


def do_dns_lookup(target, data_only):
    for d in DNS_QUERY:
        try:
            for x in DNSutils.dns_lookup(target, d, nameserver=NS):
                if data_only:
                    cliLogger.write(x)
                    fileLogger.info(x)
                else:
                    cliLogger.success("{} - ({}) {}".format(target, d, x))
                    fileLogger.info("{},{},{}".format(target, d, x))
        except Exception as e:
            logging.debug('{} - ({}) {}'.format(target, d, str(e)))


def do_reverse_lookup(target, data_only):
    try:
        for x in DNSutils.reverse_lookup(target, NS):
            if data_only:
                cliLogger.write(x)
                fileLogger.info(x)
            else:
                cliLogger.success(target + " - " + x)
                fileLogger.info(target + "," + x)
    except Exception as e:
        logging.debug('{} - {}'.format(target, str(e)))


def get_zone_transfer(target, ns):
    try:
        query = DNSutils.zone_transfer(ns, target)
        cliLogger.success('Zone Transfer {}@{}'.format(target, ns))
        for x in query:
            cliLogger.write(x)
            fileLogger.info(x)
    except Exception as e:
        logging.debug('{}@{}\t\t{}'.format(target, ns, str(e)))


def get_domain_nameserver(domain):
    return DNSutils.get_nameservers(domain, NS)


def do_zone_transfer(target):
    for n in NS if len(NS) > 0 else get_domain_nameserver(target):
        logging.debug('Testing nameserver: {}'.format(n))
        get_zone_transfer(target, n)


def main(args):
    for t in ipparser(args.target[0]):
        try:
            if args.rev:
                do_reverse_lookup(t, args.data_only)
            elif args.zonetransfer:
                do_zone_transfer(t)
            else:
                do_dns_lookup(t, args.data_only)
        except KeyboardInterrupt:
            cliLogger.warning('Key event detected, closing...', bullet='[!] ', fg='yellow')
            exit(0)


if __name__ == '__main__':
    args = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    args.add_argument('-t', dest='record', type=str, default=False, help='Type of lookup record, (optional)')
    args.add_argument('-r', dest="rev", action='store_true', help="Reverse lookup")
    args.add_argument('-z', dest="zonetransfer", action='store_true', help='Zone Transfer (-ns and target domain required)')
    args.add_argument('-ns', dest="nameserver", type=str, default=False, help="Define nameserver(s) comma separated")
    args.add_argument('--data-only', dest="data_only", action='store_true', help="Show lookup data only")
    args.add_argument('-o', dest='outfile', type=str, default=False, help='Filename to write results (optional)')
    args.add_argument('-v', dest="verbose", action='store_true', help="Show failed lookup attempts")
    args.add_argument(dest='target', nargs='+', help='Target: Domain, comma separated list, txt files, range')
    args = args.parse_args()

    DNS_QUERY = ['A', 'NS', 'MX', 'TXT', 'CNAME', 'HINFO', 'PTR', 'SOA', 'SPF', 'SRV', 'RP']
    if args.record:
        DNS_QUERY = delimiter2list(args.record)

    NS = []
    if args.nameserver:
        NS = delimiter2list(args.nameserver)

    setup_debug_logger() if args.verbose else False
    cliLogger = setup_cli_logger()
    fileLogger = setup_file_logger(args.outfile, mode='w')

    cliLogger.info(BANNER)
    main(args)

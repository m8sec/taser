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
from taser import BANNER
from sys import exit, argv
from ipparser import ipparser
from taser.dns import DNSutils
from taser.utils import delimiter2list
from taser.logx import setup_file_logger, setup_cli_logger, setup_debug_logger


def do_dns_lookup(target, data_only, query_types, nameservers, cli_logger, file_logger, no_record=False):
    data = []
    for d in query_types:
        try:
            data = DNSutils.query(target, d, ns=nameservers)
            if not data and no_record:
                cli_logger.fail("{} - ({}) No record found.".format(target, d))
            else:
                for x in data:
                    if data_only:
                        cli_logger.write(x)
                        file_logger.info(x)
                    else:
                        cli_logger.success("{} - ({}) {}".format(target, d, x))
                        file_logger.info("{},{},{}".format(target, d, x))
        except Exception as e:
            logging.debug('{} - ({}) {}'.format(target, d, str(e)))


def do_reverse_lookup(target, data_only, nameservers, cli_logger, file_logger):
    try:
        for x in DNSutils.reverse(target, nameservers):
            if data_only:
                x = x[:-1] if x.endswith('.') else x
                cli_logger.write(x)
                file_logger.info(x)
            else:
                cli_logger.success(target + " - " + x)
                file_logger.info(target + "," + x)
    except Exception as e:
        logging.debug('{} - {}'.format(target, str(e)))


def get_zone_transfer(target, ns, cli_logger, file_logger):
    try:
        query = DNSutils.zone_transfer(ns, target)
        cli_logger.success('Zone Transfer {}@{}'.format(target, ns))
        for x in query:
            cli_logger.write(x)
            file_logger.info(x)
    except Exception as e:
        cli_logger.fail('{}@{}\t\t{}'.format(target, ns, str(e)))


def get_domain_nameserver(domain, nameservers):
    return DNSutils.nameservers(domain, nameservers)


def do_zone_transfer(target, nameservers, cli_logger, file_logger):
    for n in nameservers if len(nameservers) > 0 else get_domain_nameserver(target, nameservers):
        logging.debug('Testing nameserver: {}'.format(n))
        get_zone_transfer(target, n, cli_logger, file_logger)


def main(args, query_types, nameservers, cli_logger, file_logger):
    for t in ipparser(args.target):
        try:
            if args.rev:
                do_reverse_lookup(t, args.data_only, nameservers, cli_logger, file_logger)
            elif args.zonetransfer:
                do_zone_transfer(t, nameservers, cli_logger, file_logger)
            else:
                do_dns_lookup(t, args.data_only, query_types, nameservers, cli_logger, file_logger, args.no_record)
        except KeyboardInterrupt:
            cli_logger.warning('Key event detected, closing...', bullet='[!] ', fg='yellow')
            exit(0)


def build_parser():
    parser = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    parser.add_argument('-t', '--type', type=str, default=False, help='Type of lookup record, (optional)')
    parser.add_argument('-r', dest="rev", action='store_true', help="Reverse lookup")
    parser.add_argument('-z', dest="zonetransfer", action='store_true', help='Zone Transfer (-ns and target domain required)')
    parser.add_argument('-ns', "--nameserver", type=str, default=False, help="Define nameserver(s) comma separated")
    parser.add_argument('--data-only', action='store_true', help="Show lookup data only")
    parser.add_argument('-nr', dest="no_record", action='store_true', help="Show when no record is found.")
    parser.add_argument('-o', dest='outfile', type=str, default=False, help='Filename to write results in CSV format (optional)')
    parser.add_argument('--debug', action='store_true', help='Show resolve failures')
    parser.add_argument(dest='target', nargs='+', help='Target: Domain, comma separated list, txt files, range')
    return parser


def cli(argv=None):
    args = build_parser().parse_args(argv)

    query_types = ['A', 'NS', 'MX', 'TXT', 'CNAME', 'INFO', 'PTR', 'SOA', 'SPF', 'SRV', 'RP']
    query_types = delimiter2list(args.type) if args.type else query_types
    nameservers = delimiter2list(args.nameserver) if args.nameserver else []

    setup_debug_logger() if args.debug else False
    cli_logger = setup_cli_logger()
    file_logger = setup_file_logger(args.outfile, mode='w')

    cli_logger.info(BANNER)
    main(args, query_types, nameservers, cli_logger, file_logger)


if __name__ == '__main__':
    cli()

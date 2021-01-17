#!/usr/bin/env python3
# Author: @m8r0wn
#
# Perform DNS & reverse DNS lookups and test zone transfers.
#
# python3 dnslookup.py -t A HostFile.txt
# python3 dnslookup.py -r 8.8.8.8

import argparse
from sys import exit, argv
from ipparser import ipparser
from taser.version import BANNER
from taser.utils import delimiter2list
from taser.proto.dns import dns_lookup, reverse_lookup, zone_transfer, get_nameServers
from taser.logx import setup_fileLogger, setup_consoleLogger

DNS_QUERY = ['A','NS','MX','TXT','CNAME','HINFO','PTR','SOA','SPF','SRV','RP']
NS = []

def dns_type(targets, data_only):
    for t in targets:
        for d in DNS_QUERY:
            try:
                for x in dns_lookup(t, d, nameserver=NS):
                    if data_only:
                        cliLogger.write(x)
                        fileLogger.info(x)
                    else:
                        cliLogger.success("{} - ({}) {}".format(t, d, x))
                        fileLogger.info("{}\t{}\t{}".format(t, d, x))
            except Exception as e:
                if args.verbose:
                    cliLogger.fail('{} - ({}) {}'.format(t, d, str(e)))

def reverse_dns(targets, data_only):
    for t in targets:
        try:
            for x in reverse_lookup(t):
                if data_only:
                    cliLogger.write(x)
                    fileLogger.info(x)
                else:
                    cliLogger.success(t + " - " + x)
                    fileLogger.info(t + "," + x)
        except Exception as e:
            if args.verbose:
                cliLogger.fail('{} - {}'.format(t, str(e)))

def get_domainNS(domain):
    try:
        return get_nameServers(domain, NS)
    except:
        return NS

def get_zoneTransfer(target, ns):
    try:
        query = zone_transfer(ns, target)
        cliLogger.success('Zone Transfer {}@{}'.format(target, ns))
        fileLogger.info('Zone Transfer {}@{}'.format(target, ns))

        for x in query:
            cliLogger.write(x)
            fileLogger.info(x)
    except Exception as e:
        if args.verbose:
            cliLogger.fail('{}@{}\t\t{}'.format(target, ns, str(e)))

def zoneTransfer(targets, ns=False):
    for t in targets:
        if ns:
            get_zoneTransfer(t, ns)
        else:
            for n in get_domainNS(t):
                get_zoneTransfer(t, n)

def main(args):
    try:
        if args.rev:
            reverse_dns(args.target, args.data_only)
        elif args.zonetransfer:
            zoneTransfer(args.target, ns=args.nameserver)
        else:
            dns_type(args.target, args.data_only)
    except KeyboardInterrupt:
        cliLogger.warning('Key event detected, closing...', bullet='[!] ', fg='yellow')
        exit(0)

if __name__ == '__main__':
    args = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    args.add_argument('-t', dest='record', type=str, default=False, help='Type of lookup record, (optional)')
    args.add_argument('-r', dest="rev", action='store_true', help="Reverse DNS lookup")
    args.add_argument('-z', dest="zonetransfer", action='store_true', help='Zone Transfer (-ns and target domain required)')
    args.add_argument('-ns', dest="nameserver", type=str, default=False, help="Define nameserver(s) comma separated")
    args.add_argument('--data-only', dest="data_only", action='store_true', help="Show lookup data only")
    args.add_argument('-o', dest='outfile', action='store', help='Filename to write results (optional)')
    args.add_argument('-v', dest="verbose", action='store_true', help="Show failed lookup attempts")
    args.add_argument(dest='target', nargs='+', help='Target: Domain, comma separated list, txt files, range')
    args = args.parse_args()

    args.target = ipparser(args.target[0])

    if args.record:
        DNS_QUERY = delimiter2list(args.record)
    if args.nameserver:
        NS = delimiter2list(args.nameserver)

    cliLogger = setup_consoleLogger()
    fileLogger = setup_fileLogger(args.outfile, mode='w')

    cliLogger.info(BANNER)
    main(args)
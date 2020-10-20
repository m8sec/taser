#!/usr/bin/env python3
# Author: @m8r0wn
#
# Perform DNS and reverse DNS lookups
#
# python3 dnslookup.py -t A HostFile.txt
# python3 dnslookup.py -r 8.8.8.8

import argparse
from sys import exit, argv
from ipparser import ipparser
from taser.version import BANNER
from taser.proto.dns import dns_lookup, reverse_lookup
from taser.logx import setup_fileLogger, setup_consoleLogger

DNS_TYPES = ['A','NS','MX','TXT','CNAME','HINFO','PTR','SOA','SPF','SRV','RP']

def dns_type(targets, type, data_only):
    for t in targets:
        if 'all' in type.lower():
            for d in DNS_TYPES:
                results = dns_lookup(t, d)
                for x in results:
                    if data_only:
                        cliLogger.write(x)
                        fileLogger.info(x)
                    else:
                        cliLogger.success("{} - ({}) {}".format(t, d, x))
                        fileLogger.info("{}\t{}\t{}".format(t, d, x))
        else:
            results = dns_lookup(t, args.record)
            for x in results:
                if data_only:
                    cliLogger.write(x)
                    fileLogger.info(x)
                else:
                    cliLogger.success("{} - ({}) {}".format(t, type, x))
                    fileLogger.info("{}\t{}\t{}".format(t, type, x))

def reverse_dns(targets, data_only):
    for t in targets:
        results = reverse_lookup(t)
        if results:
            for x in results:
                if data_only:
                    cliLogger.write(x)
                    fileLogger.info(x)
                else:
                    cliLogger.success(t + " - " + x)
                    fileLogger.info(t + "," + x)

def main(args):
    try:
        # DNS lookup
        if args.record:
            dns_type(args.target, args.record,args.data_only)
        # Reverse DNS Lookup
        elif args.rev:
            reverse_dns(args.target, args.data_only)
    except KeyboardInterrupt:
        cliLogger.warning('Key event detected, closing...', bullet='[!] ', fg='yellow')
        exit(0)

if __name__ == '__main__':
    args = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    args.add_argument('-t', dest='record', type=str, default='all', help='Type of lookup record, (Default: all)')
    args.add_argument('-r', dest="rev", action='store_true', help="Reverse DNS lookup")
    args.add_argument('-d','--data-only', dest="data_only", action='store_true', help="Show lookup data only")
    args.add_argument('-o', dest='outfile', action='store', help='Filename to write results (optional)')
    args.add_argument(dest='target', nargs='+', help='Target: Domain, comma separated list, txt files, range')
    args = args.parse_args()

    args.target = ipparser(args.target[0])

    cliLogger = setup_consoleLogger()
    fileLogger = setup_fileLogger(args.outfile, mode='w')

    cliLogger.info(BANNER)
    main(args)
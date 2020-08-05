#!/usr/bin/env python3
# Author: @m8r0wn
#
# Simple script to perform DNS and reverse DNS lookups
#
# python3 dnslookup.py -t A HostFile.txt
# python3 dnslookup.py -r 8.8.8.8

import argparse
from sys import exit
from ipparser import ipparser
from taser.printx import bullet, colored
from taser.proto.dns import dns_lookup, reverse_lookup

DNS_TYPES = ['A','NS','MX','TXT','CNAME','HINFO','PTR','SOA','SPF','SRV','RP']

def dns_type(targets, type, data_only):
    print('DNS Lookup')
    colored('-' * 25, fg='gray')
    for t in targets:
        if 'all' in type.lower():
            for d in DNS_TYPES:
                results = dns_lookup(t, d)
                for x in results:
                    if data_only:
                        print(x)
                    else:
                        bullet("{} - ({}) {}".format(t, d, x), bullet='[+] ', bullet_fg='green')
        else:
            results = dns_lookup(t, args.record)
            for x in results:
                if data_only:
                    print(x)
                else:
                    bullet("{} - ({}) {}".format(t, type, x), bullet='[+] ', bullet_fg='green')

def reverse_dns(targets, data_only):
    print('Reverse DNS Lookup')
    colored('-' * 25, fg='gray')
    for t in targets:
        results = reverse_lookup(t)
        if results:
            for x in results:
                if data_only:
                    print(x)
                else:
                    bullet(t + " - " + x)

def main(args):
    try:
        # DNS lookup
        if args.record:
            dns_type(args.target, args.record,args.data_only)
        # Reverse DNS Lookup
        elif args.rev:
            reverse_dns(args.target, args.data_only)
    except KeyboardInterrupt:
        bullet("Key event detected, closing...", bullet='[!]', bullet_fg='yellow')
        exit(0)

if __name__ == '__main__':
    args = argparse.ArgumentParser()
    args.add_argument('-t', dest='record', type=str, default='all', help='Type of lookup record, (Default: all)')
    args.add_argument('-r', dest="rev", action='store_true', help="Reverse DNS lookup")
    args.add_argument('-d', dest="data_only", action='store_true', help="Show lookup data only")
    args.add_argument(dest='target', nargs='+', help='Target: Domain, comma separated list, txt files, range')
    args = args.parse_args()
    args.target = ipparser(args.target[0])
    main(args)
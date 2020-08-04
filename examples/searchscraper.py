#!/usr/bin/env python3
# Author: @m8r0wn
#
# Perform Google and Bing search queries using Taser request/evasion methods
# and get a list of resulting links.
#
# searchscraper.py -s bing -o bing_search.txt 'domain:example.com'

import argparse
import threading
from os import _exit
from time import sleep
from taser.utils import file_exists
from taser.proto.http.websearch import WebSearch
from taser.logx import setup_fileLogger, setup_consoleLogger

class ExWebScraper(WebSearch):
    def __init__(self, search_engine='bing', search_query='', timeout=30, conn_timeout=3, proxies=[]):
        WebSearch.__init__(self, search_engine, search_query, timeout, conn_timeout, proxies)

    def linkHander(self, url, search_engine, search_query):
        if url not in self.links:
            self.links.append(url)
            cliLogger.success(url, bullet='[{}-RESULT] '.format(search_engine.upper()), fg='green')
            fileLogger.info('''{},{},{}'''.format(search_engine.upper(),search_query,url))

def main(args):
    s = ExWebScraper(args.search_engine, args.query[0],timeout=args.timeout, conn_timeout=args.conn_timeout, proxies=args.proxy)
    s.start()

    while threading.active_count() > 1:
        try:
            sleep(0.01)
        except KeyboardInterrupt:
            cliLogger.warning('Key event detected.', bullet='[CLOSING] ', fg='yellow')
            _exit(0)

if __name__ == '__main__':
    args = argparse.ArgumentParser()
    args.add_argument('-t', dest='timeout', type=int, default=30, help='Spider timeout (Default: 30)')
    args.add_argument('-tc', dest='conn_timeout', type=int, default=3, help='Connection timeout')
    args.add_argument('-o', dest='outfile', action='store', help='Output to filename to log results')
    proxy = args.add_mutually_exclusive_group(required=False)
    proxy.add_argument('--proxy', dest='proxy', action='append', default=[], help='Proxy requests (IP:Port)')
    proxy.add_argument('--proxy-file', dest='proxy', default=False, type=lambda x: file_exists(args, x), help='Load proxies from file for rotation')
    args.add_argument('-s', dest='search_engine', choices=['bing', 'google'], default='bing',help='Search Engine (Default:bing)')
    args.add_argument(dest='query', nargs='+', help='Search Engine Query [Positional]')
    args = args.parse_args()

    cliLogger = setup_consoleLogger(spacers=[30])
    fileLogger = setup_fileLogger(args.outfile, mode='w')
    fileLogger.info('''SOURCE,SEARCH,URL''')

    main(args)
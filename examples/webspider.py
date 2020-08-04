#!/usr/bin/env python3
# Author: @m8r0wn
#
# Recursively spider a website and display all links found on the site
#
# python3 webspider.py -o spider_results.txt https://example.com

import argparse
import threading
from os import _exit
from time import sleep
from taser.utils import file_exists
from taser.proto.http import extract_subdomain
from taser.proto.http.spider import Spider
from taser.logx import setup_fileLogger, setup_consoleLogger

class TaserSpider(Spider):
    def __init__(self, url, depth, timeout, conn_timeout, proxies):
        Spider.__init__(self, url, depth, timeout, conn_timeout, proxies)

    def outputHandler(self, url, src_url):
        subdomain = extract_subdomain(url).lower()

        if url.startswith('mailto'):
            cliLogger.success([src_url, ' => ', url], bullet='[EMAIL] ', fg='green')
            fileLogger.info('''EMAIL,{},{}'''.format(src_url, url))

        elif self.base_domain in subdomain:
            if self.base_subdomain != subdomain:
                cliLogger.success([src_url, ' => ', url], bullet='[SUBDOMAIN] ', fg='red')
                fileLogger.info('''SUBDOMAIN,{},{}'''.format(src_url, url))
            else:
                cliLogger.success([src_url, ' => ', url], bullet='[URL] ', fg='blue')
                fileLogger.info('''URL,{},{}'''.format(src_url, url))

        else:
            cliLogger.success([src_url, ' => ', url], bullet='[EXTERNAL-URL] ', fg='purple')
            fileLogger.info('''ExternalURL,{},{}'''.format(src_url,url))


def spider(url, depth=2, timeout=30, conn_timeout=3, proxies=[]):
    s = TaserSpider(url, depth, timeout, conn_timeout, proxies)
    s.start()

    while threading.active_count() > 1:
        try:
            sleep(0.03)
        except KeyboardInterrupt:
            cliLogger.warning('Key event detected.', bullet='[CLOSING] ', fg='yellow')
            _exit(0)
    return

if __name__ == '__main__':
    args = argparse.ArgumentParser()
    args.add_argument('-t', dest='timeout', type=int, default=30, help='Spider timeout (Default: 30)')
    args.add_argument('-tc', dest='conn_timeout', type=int, default=3, help='Connection timeout')
    args.add_argument('-d', dest='depth', type=int, default=2, help='Spider depth (Default: 2)')
    args.add_argument('-o', dest='outfile', action='store', help='Output to filename to log results')
    proxy = args.add_mutually_exclusive_group(required=False)
    proxy.add_argument('--proxy', dest='proxy', action='append', default=[], help='Proxy requests (IP:Port)')
    proxy.add_argument('--proxy-file', dest='proxy', default=False, type=lambda x: file_exists(args, x), help='Load proxies from file for rotation')
    args.add_argument(dest='target', nargs='+', help='Target website to crawl')
    args = args.parse_args()

    cliLogger = setup_consoleLogger(spacers=[30])
    fileLogger = setup_fileLogger(args.outfile, mode='w')
    fileLogger.info('''Detection,Source,URL''')

    if not args.target[0].startswith(('http://', 'https://')):
        args.target[0] = 'https://'+args.target[0]

    spider(args.target[0], args.depth, args.timeout, args.conn_timeout, args.proxy)
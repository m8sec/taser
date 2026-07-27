#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Extend Taser spider to discover:
#   - Subdomains
#   - Emails
#   - Comments
#   - Secrets in source code
#   - Broken backlinks
#
# Usage:
# python3 webspider.py --subdomains https://test.com
# python3 webspider.py --links https://test.com
# python3 webspider.py --comments --backlinks https://test.com
import re
import logging
import warnings
import argparse
import threading
from sys import argv
from os import _exit
from time import sleep
from ipparser import ipparser
from taser.http import spider
from taser import BANNER
from bs4 import BeautifulSoup, Comment
from urllib3 import disable_warnings, exceptions

from taser.http.parser import URLParser
from taser.resources import SECRET_PATTERNS
from taser.utils import delimiter2dict, file_exists
from taser.logx import setup_file_logger, setup_cli_logger, setup_debug_logger
from taser.http import web_request, get_statuscode, extract_links, extract_header

disable_warnings(exceptions.InsecureRequestWarning)                     # Prevent SSL warnings & cert verification msg
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')   # Hide parser msg
logging.getLogger("charset_normalizer").setLevel(logging.WARNING)       # Hide "encoding detected" msg


class TaserSpider(spider.Spider):
    def __init__(self, url, depth, timeout, conn_timeout, headers=None, proxies=None, options=None, cli_logger=None, file_logger=None):
        headers = headers or {}
        proxies = proxies or []
        spider.Spider.__init__(self, url, depth, timeout, conn_timeout, headers, proxies)
        self.options = options
        self.cli_logger = cli_logger
        self.file_logger = file_logger
        self.set_regex()

        # Enumeration arrays
        self._subdomains = []
        self._emails = []
        self._dups = set()

    def set_regex(self):
        self.regex_js_comment = r'\/\*.*\*\/|https\:\/\/.*|http\:\/\/.*|\/\/.*'
        self.regex_email = r'^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$'
        self.regex_subdomain = r'[%\\]?[a-zA-Z0-9][a-zA-Z0-9-_.]*\.{}'.format(self.base_subdomain)
        self.regex_secrets = SECRET_PATTERNS

    # Override_method
    def spider_test(self):
        r = web_request(self._queue[0][0], timeout=self.conn_timeout, headers=self.headers, proxies=self.proxies)
        if get_statuscode(r):
            self.init_queue(r.url)                                              # Adjust to any redirects www.*
            self.base_domain = URLParser.extract_webdomain(r.request.url).lower()     # Reset base domain
            self.base_subdomain = URLParser.extract_subdomain(r.request.url).lower()  # Reset subdomain
            self.set_regex()                                                          # Reset regex for updated values
            return True
        return False

    # Override_method
    # Determines which pages or items are parsed from the HTTP Response
    def parse(self, resp, next_depth):
        # 404 Internal Backlinks
        if self.options.backlinks and resp.status_code in [404]:
            self.cli_logger.success('{} => {}'.format(resp.request.url, resp.url), bullet='[404-INTERNAL] ', fg='green')
            self.file_logger.info('"404-INTERNAL","{}","{}"'.format(resp.request.url, resp.url))

        # Parse .js & .jsx files
        if extract_header('Content-Type', resp).startswith('application/x-javascript') or any(m in resp.request.url for m in ['.js', '.jsx']):
            self.js_handler(resp.text, resp)

        # Parse HTML & in-line JavaScript
        if extract_header('Content-Type', resp).startswith('text/html'):
            for url in extract_links(resp, mailto=True, source={'a': 'href', 'script': 'src', 'link': 'href'}):
                self.link_handler(url, next_depth)
                self.enum_html_links(url, resp)
            self.get_inline_js(resp)
            self.enum_html_comments(resp)

    # Parse HTML for inline JS before sending to handler
    def get_inline_js(self, resp):
        soup = BeautifulSoup(resp.content, "lxml")
        for js in soup.find_all("script"):
            self.js_handler(js, resp)

    # JS pages and inline JS flows through handler
    def js_handler(self, data, resp):
        self.enum_js_comments(data, resp)
        self.enum_js_emails(data, resp)
        self.enum_js_subdomains(data, resp)
        self.enum_js_secrets(data, resp)

    ###################################
    # Output methods based on cmd args
    ###################################
    def enum_external_backlinks(self, src_url, url):
        if self.options.backlinks:
            if get_statuscode(web_request(url, timeout=self.conn_timeout, proxies=self.proxies)) in [404, 0]:
                self.cli_logger.success('{} => {}'.format(src_url, url), bullet='[404-EXTERNAL] ', fg='green')
                self.file_logger.info('"404-EXTERNAL","{}","{}"'.format(src_url, url))

    def enum_js_emails(self, data, resp):
        if self.options.emails:
            for match in re.findall(self.regex_email, str(data)):
                if match not in self._emails:
                    self.cli_logger.success('{} => {}'.format(resp.url, match), bullet='[JS-EMAIL] ', fg='blue')
                    self.file_logger.info('"JS-EMAIL","{}","{}"'.format(resp.url, match))
                    self._emails.append(match)

    def enum_js_subdomains(self, data, resp):
        if self.options.subdomains:
            for match in re.findall(self.regex_subdomain, str(data)):
                if match not in self._subdomains:
                    self.cli_logger.success('{} => {}'.format(resp.url, match), bullet='[JS-SUBDOMAIN] ', fg='yellow')
                    self.file_logger.info('"JS-SUBDOMAIN","{}","{}"'.format(resp.url, match))
                    self._subdomains.append(match)

    def enum_js_secrets(self, data, resp):
        if self.options.secrets:
            for k, r in self.regex_secrets.items():
                for match in re.findall(r, str(data)):
                    self.cli_logger.success('{} => {}'.format(resp.url, match), bullet='[JS-SECRET::{}] '.format(k), fg='cyan')
                    self.file_logger.info('"JS-SECRET:","{}","{}"'.format(resp.url, match))

    def enum_html_links(self, url, resp):
        url = url
        src_url = resp.url
        subdomain = URLParser.extract_subdomain(url).lower()

        # HTML - Emails
        if url.startswith('mailto:'):
            email = url.split(':')[1].split("?")[0]
            if email and self.options.emails and email not in self._emails:
                self._emails.append(email)
                self.cli_logger.success('{} => {}'.format(src_url, email), bullet='[HTML-EMAIL] ', fg='blue')
                self.file_logger.info('"HTML-EMAIL","{}","{}"'.format(src_url, email))

        elif self.base_subdomain == subdomain:
            # HTML - Site Links
            if self.options.links:
                self.cli_logger.success('{} => {}'.format(src_url, url), bullet='[HTML-LINK] ', fg='blue')
                self.file_logger.info('"HTML-LINK","{}","{}"'.format(src_url, url))

        elif self.base_domain in subdomain:
            # HTML - Subdomains
            if self.options.subdomains and subdomain.lower() not in self._subdomains:
                self._subdomains.append(subdomain.lower())
                self.cli_logger.success('{} => {}'.format(src_url, subdomain), bullet='[HTML-SUBDOMAIN] ', fg='yellow')
                self.file_logger.info('"HTML-SUBDOMAIN","{}","{}"'.format(src_url, subdomain))

        else:
            # HTML - External Links
            if self.options.external:
                self.cli_logger.success('{} => {}'.format(src_url, url), bullet='[HTML-EXTERNAL] ', fg='purple')
                self.file_logger.info('"HTML-EXTERNAL","{}","{}"'.format(src_url, url))

            # HTML - External Backlinks
            if self.options.backlinks:
                self.enum_external_backlinks(src_url, url)

    def enum_html_comments(self, resp):
        if self.options.comments:
            soup = BeautifulSoup(resp.content, "lxml")
            for c in soup.find_all(string=lambda text: isinstance(text, Comment)):
                tmp_id = f'{resp.url.lower()}__{c.lower()}'
                if tmp_id not in self._dups:
                    self._dups.add(tmp_id)
                    self.cli_logger.success('{} => {}'.format(resp.url, c), bullet='[HTML-COMMENT] ', fg='cyan')
                    self.file_logger.info('"HTML-COMMENT","{}","{}"'.format(resp.url, c))

    def enum_js_comments(self, data, resp):
        if self.options.comments:
            for match in re.findall(self.regex_js_comment, str(data)):
                tmp_id = f'{resp.url.lower()}__{match.lower()}'
                if not match.startswith(('https:', 'http:')) and tmp_id not in self._dups:
                    self._dups.add(tmp_id)
                    self.cli_logger.success('{} => {}'.format(resp.url, match), bullet='[JS-COMMENT] ', fg='cyan')
                    self.file_logger.info('"JS-COMMENT","{}","{}"'.format(resp.url, match))


def build_parser():
    parser = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    parser.add_argument('--debug', action='store_true', help="Enable debug logging")
    parser.add_argument('-d', '--depth', type=int, default=2, help='Spider depth (Default: 2)')
    parser.add_argument('-T', dest='max_threads', type=int, default=10, help='Max Threads')
    parser.add_argument('-st', dest='timeout', type=int, default=30, help='Spider timeout (Default: 20)')
    parser.add_argument('-o', dest='outfile', action='store', help='Filename to log results')

    req = parser.add_argument_group("Request Options")
    req.add_argument('-C', '--cookie', type=str, default=False, help='Add Cookie (\'name1=123; name2=456\')')
    req.add_argument('-H', dest='header', type=str, default='', help='Add Header (\'name1:value1;name2:value2\')')
    req.add_argument('-t', dest='conn_timeout', type=int, default=3, help='Connection timeout')

    enum = parser.add_argument_group("Enumeration Options")
    enum.add_argument('--links', action='store_true', help='Site Links [HTML]')
    enum.add_argument('--external', action='store_true', help='External Links [HTML]')
    enum.add_argument('--emails', action='store_true', help='Emails [HTML & JS]')
    enum.add_argument('--subdomains', action='store_true', help='Subdomains [HTML & JS]')
    enum.add_argument('--secrets', action='store_true', help='Secrets [JS]')
    enum.add_argument('--comments', action='store_true', help='Comments [HTML & JS]')
    enum.add_argument('--backlinks', action='store_true', help='Broken backlinks [HTML]')

    proxy = parser.add_argument_group("Proxy Options")
    p = proxy.add_mutually_exclusive_group(required=False)
    p.add_argument('--proxy', dest='proxy', action='append', default=[], help='Proxy requests (IP:Port)')
    p.add_argument('--proxy-file', dest='proxy', default=False, type=lambda x: file_exists(parser, x), help='Load proxies from file')

    parser.add_argument(dest='target', nargs='+', help='Target URL(s)')
    return parser


def cli(argv=None):
    args = build_parser().parse_args(argv)

    cli_logger = setup_cli_logger()
    cli_logger.info(BANNER)

    setup_debug_logger() if args.debug else False
    file_logger = setup_file_logger(args.outfile, mode='w')
    file_logger.info('''"Detection","Source","Match"''')

    headers = delimiter2dict(args.header, delim_one=";", delim_two=":")
    if args.cookie: headers['Cookie'] = args.cookie

    try:
        for target in ipparser(args.target[0]):

            url = "https://"+target if not target.startswith(('http://', 'https://')) else target
            cli_logger.info('Launching JS spider against {}'.format(url), bullet='[STATUS] ')
            TaserSpider(url, args.depth, args.timeout, args.conn_timeout, headers, args.proxy, options=args, cli_logger=cli_logger, file_logger=file_logger).start()
            while threading.active_count() >= args.max_threads:
                sleep(0.5)
        while threading.active_count() > 1:
            sleep(0.5)
    except KeyboardInterrupt:
        cli_logger.warning('Key event detected.', bullet='[CLOSING] ', fg='yellow')
        _exit(0)


if __name__ == '__main__':
    cli()

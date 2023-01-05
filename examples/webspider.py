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
import argparse
import threading
from sys import argv
from os import _exit
from time import sleep
from ipparser import ipparser
from taser.http import spider
from taser.version import BANNER
from bs4 import BeautifulSoup, Comment

from taser.http.parser import URLParser
from taser.utils import delimiter2dict
from taser.logx import setup_file_logger, setup_cli_logger
from taser.http import web_request, get_statuscode, extract_links


class TaserSpider(spider.Spider):
    def __init__(self, url, depth, timeout, conn_timeout, headers={}, proxies=[]):
        spider.Spider.__init__(self, url, depth, timeout, conn_timeout, headers, proxies)
        self.set_regex()

        # Enumeration arrays
        self._subdomains = []
        self._emails = []

    def set_regex(self):
        self.regex_js_comment = r'\/\*.*\*\/|https\:\/\/.*|http\:\/\/.*|\/\/.*'
        self.regex_email = r'^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$'
        self.regex_subdomain = r'[%\\]?[a-zA-Z0-9][a-zA-Z0-9-_.]*\.{}'.format(self.base_subdomain)
        self.regex_secrets = {
            'google_api': r'AIza[0-9A-Za-z-_]{35}',
            'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
            'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
            'amazon_aws_access_key_id': r'A[SK]IA[0-9A-Z]{16}',
            'amazon_mws_auth_toke': r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'amazon_aws_url': r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
            'amazon_aws_url2': r"(" \
                   r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
                   r"|s3://[a-zA-Z0-9-\.\_]+" \
                   r"|s3-[a-zA-Z0-9-\.\_\/]+" \
                   r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
                   r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
            'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'authorization_basic': r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
            'authorization_bearer': r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
            'authorization_api': r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
            'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
            'twilio_api_key': r'SK[0-9a-fA-F]{32}',
            'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
            'twilio_app_sid': r'AP[a-zA-Z0-9_\-]{32}',
            'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            'square_oauth_secret': r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
            'square_access_token': r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
            'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
            'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
            'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
            'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
            'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
            'ssh_dc_private_key': r'-----BEGIN EC PRIVATE KEY-----',
            'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'json_web_token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
            'slack_token': r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
            'SSH_privKey': r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
            'Heroku API KEY': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'possible_Creds': r"(?i)(" \
                            r"password\s*[`=:\"]+\s*[^\s]+|" \
                            r"password is\s*[`=:\"]*\s*[^\s]+|" \
                            r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                            r"passwd\s*[`=:\"]+\s*[^\s]+)"
        }

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
        if args.backlinks and resp.status_code in [404]:
            cliLogger.success('{} => {}'.format(resp.request.url, resp.url), bullet='[404-INTERNAL] ', fg='green')
            fileLogger.info('"404-INTERNAL","{}","{}"'.format(resp.request.url, resp.url))

        # Parse .js & .jsx files
        if resp.headers['Content-Type'].startswith('application/x-javascript') or any(m in resp.request.url for m in ['.js', '.jsx']):
            self.js_handler(resp.text, resp)

        # Parse HTML & in-line JavaScript
        if resp.headers['Content-Type'].startswith('text/html'):
            for url in extract_links(resp, mailto=True, source={'a': 'href', 'script': 'src', 'link': 'href'}):
                self.link_handler(url, next_depth)
                self.enum_html_links(url, resp)
            self.get_inline_js(resp)
            self.enum_html_comments(resp)

    # Parse HTML for inline JS before sending to handler
    def get_inline_js(self, resp):
        soup = BeautifulSoup(resp.content, "lxml")
        for js in soup.findAll("script"):
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
        if args.backlinks:
            if get_statuscode(web_request(url, timeout=self.conn_timeout, proxies=self.proxies)) in [404]:
                cliLogger.success('{} => {}'.format(src_url, url), bullet='[404-EXTERNAL] ', fg='green')
                fileLogger.info('"404-EXTERNAL","{}","{}"'.format(src_url, url))

    def enum_js_emails(self, data, resp):
        if args.emails:
            for match in re.findall(self.regex_email, str(data)):
                if match not in self._emails:
                    cliLogger.success('{} => {}'.format(resp.url, match), bullet='[JS-EMAIL] ', fg='blue')
                    fileLogger.info('"JS-EMAIL","{}","{}"'.format(resp.url, match))
                    self._emails.append(match)

    def enum_js_subdomains(self, data, resp):
        if args.subdomains:
            for match in re.findall(self.regex_subdomain, str(data)):
                if match not in self._subdomains:
                    cliLogger.success('{} => {}'.format(resp.url, match), bullet='[JS-SUBDOMAIN] ', fg='yellow')
                    fileLogger.info('"JS-SUBDOMAIN","{}","{}"'.format(resp.url, match))
                    self._subdomains.append(match)

    def enum_js_secrets(self, data, resp):
        if args.secrets:
            for k, r in self.regex_secrets.items():
                for match in re.findall(r, str(data)):
                    cliLogger.success('{} => {}'.format(resp.url, match), bullet='[JS-SECRET] ', fg='cyan')
                    fileLogger.info('"JS-SECRET","{}","{}"'.format(resp.url, match))

    def enum_html_links(self, url, resp):
        url = url
        src_url = resp.url
        subdomain = URLParser.extract_subdomain(url).lower()

        # HTML - Emails
        if url.startswith('mailto:'):
            email = url.split(':')[1].split("?")[0]
            if email and args.emails and email not in self._emails:
                self._emails.append(email)
                cliLogger.success('{} => {}'.format(src_url, email), bullet='[HTML-EMAIL] ', fg='blue')
                fileLogger.info('"HTML-EMAIL","{}","{}"'.format(src_url, email))

        elif self.base_subdomain == subdomain:
            # HTML - Site Links
            if args.links:
                cliLogger.success('{} => {}'.format(src_url, url), bullet='[HTML-LINK] ', fg='blue')
                fileLogger.info('"HTML-LINK","{}","{}"'.format(src_url, url))

        elif self.base_domain in subdomain:
            # HTML - Subdomains
            if args.subdomains and subdomain.lower() not in self._subdomains:
                self._subdomains.append(subdomain.lower())
                cliLogger.success('{} => {}'.format(src_url, subdomain), bullet='[HTML-SUBDOMAIN] ', fg='yellow')
                fileLogger.info('"HTML-SUBDOMAIN","{}","{}"'.format(src_url, subdomain))

        else:
            # HTML - External Links
            if args.external:
                cliLogger.success('{} => {}'.format(src_url, url), bullet='[HTML-EXTERNAL] ', fg='purple')
                fileLogger.info('"HTML-EXTERNAL","{}","{}"'.format(src_url, url))

            # HTML - External Backlinks
            if args.backlinks:
                self.enum_external_backlinks(src_url, url)

    def enum_html_comments(self, resp):
        if args.comments:
            soup = BeautifulSoup(resp.content, "lxml")
            for c in soup.find_all(string=lambda text: isinstance(text, Comment)):
                cliLogger.success('{} => {}'.format(resp.url, c), bullet='[HTML-COMMENT] ', fg='cyan')
                fileLogger.info('"HTML-COMMENT","{}","{}"'.format(resp.url, c))

    def enum_js_comments(self, data, resp):
        if args.comments:
            for match in re.findall(self.regex_js_comment, str(data)):
                if not match.startswith(('https:', 'http:')):
                    cliLogger.success('{} => {}'.format(resp.url, match), bullet='[JS-COMMENT] ', fg='cyan')
                    fileLogger.info('"JS-COMMENT","{}","{}"'.format(resp.url, match))


def launcher(url):
    cliLogger.info('Launching JS spider agaist {}'.format(url), bullet='[STATUS] ')
    TaserSpider(url, args.depth, args.timeout, args.conn_timeout, headers, args.proxy).start()

    while threading.active_count() > 1:
        try:
            sleep(0.5)
        except KeyboardInterrupt:
            cliLogger.warning('Key event detected.', bullet='[CLOSING] ', fg='yellow')
            _exit(0)


if __name__ == '__main__':
    args = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    args.add_argument('-d', '--depth', type=int, default=2, help='Spider depth (Default: 2)')
    args.add_argument('-T', dest='timeout', type=int, default=30, help='Spider timeout (Default: 20)')
    args.add_argument('-o', dest='outfile', action='store', help='Filename to log results')

    req = args.add_argument_group("Request Options")
    req.add_argument('-C', '--cookie', type=str, default=False, help='Add Cookie (\'name1=123; name2=456\')')
    req.add_argument('-H', dest='header', type=str, default='', help='Add Header (\'name1=value1;name2=value2\')')
    req.add_argument('-t', dest='conn_timeout', type=int, default=3, help='Connection timeout')

    enum = args.add_argument_group("Enumeration Options")
    enum.add_argument('--links', action='store_true', help='Site Links [HTML]')
    enum.add_argument('--external', action='store_true', help='External Links [HTML]')
    enum.add_argument('--emails', action='store_true', help='Emails [HTML & JS]')
    enum.add_argument('--subdomains', action='store_true', help='Subdomains [HTML & JS]')
    enum.add_argument('--secrets', action='store_true', help='Secrets [JS]')
    enum.add_argument('--comments', action='store_true', help='Comments [HTML & JS]')
    enum.add_argument('--backlinks', action='store_true', help='Broken backlinks [HTML]')

    proxy = args.add_argument_group("Proxy Options")
    p = proxy.add_mutually_exclusive_group(required=False)
    p.add_argument('--proxy', dest='proxy', action='append', default=[], help='Proxy requests (IP:Port)')
    p.add_argument('--proxy-file', dest='proxy', default=False, type=lambda x: file_exists(args, x), help='Load proxies from file')

    args.add_argument(dest='target', nargs='+', help='Target URL(s)')
    args = args.parse_args()

    cliLogger = setup_cli_logger()
    cliLogger.info(BANNER)

    fileLogger = setup_file_logger(args.outfile, mode='w')
    fileLogger.info('''"Detection","Source","Match"''')

    headers = delimiter2dict(args.header)
    if args.cookie: headers['Cookie'] = args.cookie

    for target in ipparser(args.target[0]):
        target = "https://"+target if not target.startswith(('http://', 'https://')) else target
        launcher(target)



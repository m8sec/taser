#!/usr/bin/env python3
# Author: @m8r0wn
#
# Recursively spider a website for sensitive information in HTML, in-line
# JavaScript, & JavaScript resource files.
#
# The goal of jsearch.py was to showcase the versatility of taser's Spider and ability to
# extend it's capabilities... There was no need to recreate the wheel for parsing JavaScript
# with regex. Thank you to the following projects for helping with this aspect of the code.
#    https://github.com/m4ll0k/SecretFinder
#    https://github.com/Cillian-Collins/subscraper
#
# Feel free to help here and add more :)
#
# python3 jsearch.py -o output.txt https://www.example.com

import re
import argparse
import threading
from sys import argv
from os import _exit
from time import sleep
from bs4 import BeautifulSoup
from ipparser import ipparser

from taser.version import BANNER
from taser.utils import file_exists, ipcheck
from taser.proto.http.spider import Spider
from taser.logx import setup_fileLogger, setup_consoleLogger
from taser.proto.http import extract_webdomain, extract_subdomain, extract_links

class JSearch(Spider):
    def __init__(self, url, depth, timeout, conn_timeout, proxies, debug=False):
        Spider.__init__(self, url, depth, timeout, conn_timeout, proxies=proxies)
        self.debug = debug
        self.subdomains = [extract_subdomain(url)]
        self.emails = []
        self.blacklist = ['google', 'cloudflare', 'modernizer', 'jquery', 'bootstrap']
        self.regex = {
            'subdomain': r"[%\\]?[a-zA-Z0-9][a-zA-Z0-9-_.]*\.{}".format(extract_webdomain(url)),
            'email': r"/[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*",
            'google_api': r'AIza[0-9A-Za-z-_]{35}',
            'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
            'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
            'amazon_aws_access_key_id': r'AKIA[0-9A-Z]{16}',
            'amazon_mws_auth_toke': r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'amazon_aws_url': r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
            'amazon_aws_url2': r"(" \
                               r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
                               r"|s3://[a-zA-Z0-9-\.\_]+" \
                               r"|s3-[a-zA-Z0-9-\.\_\/]+" \
                               r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
                               r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
            'firebase.io_url': r'firebase.io',
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
            'possible_Creds': r"(?i)(" \
                              r"password\s*[`=:\"]+\s*[^\s]+|" \
                              r"password is\s*[`=:\"]*\s*[^\s]+|" \
                              r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                              r"passwd\s*[`=:\"]+\s*[^\s]+)",
        }

    def pageParser(self, resp, next_depth):
        if resp.headers['Content-Type'].startswith('application/x-javascript') or any(m in resp.request.url for m in ['.js','jsx']):
            self.js_parser(resp.text, resp.request.url)

        elif resp.headers['Content-Type'].startswith('text/html'):
            for url in extract_links(resp, mailto=True, source={'a':'href', 'script':'src', 'link':'href'}):
                self.linkHandler(url.strip(), resp.request.url, next_depth)
                self.outputHandler(url.strip(), resp.request.url)
            soup = BeautifulSoup(resp.content, "lxml")
            js_tags = soup.findAll("script")
            for js in js_tags:
                self.js_parser(js, resp.request.url)

    def outputHandler(self, link, src_url):
        subdomain = extract_subdomain(link).lower()
        if link.startswith('mailto'):
            email = link.split(':')[1].split("?")[0]
            if email not in self.emails:
                self.emails.append(email)
                cliLogger.success('{} => {}'.format(src_url, email), bullet='[HTML-EMAIL] ', fg='blue')
                fileLogger.info('''HTML-EMAIL,{},{}'''.format(src_url, email))

        elif self.base_domain in subdomain and self.base_domain != subdomain:
            if  subdomain.lower() not in self.subdomains:
                self.subdomains.append(subdomain.lower())
                cliLogger.success('{} => {}'.format(src_url, subdomain), bullet='[HTML-SUBDOMAIN] ', fg='blue')
                fileLogger.info('''HTML-SUBDOMIAN,{},{}'''.format(src_url, subdomain))

        elif ipcheck(subdomain):
            cliLogger.success('{} => {}'.format(src_url, link), bullet='[HTML-IP] ', fg='blue')
            fileLogger.info('''HTML-IP,{},{}'''.format(src_url, link))

        elif args.spider:
            if self.base_domain in subdomain:
                cliLogger.info('{} => {}'.format(src_url, link), bullet='[HTML-SPIDER] ')
            else:
                cliLogger.success([src_url, ' => ', link], bullet='[HTML-EXTERNAL] ', fg='purple')
            fileLogger.info('''HTML-SPIDER,{},{}'''.format(src_url, link))

    def js_parser(self, text, url):
        if any(x in url for x in self.blacklist):
            return
        for key,regex in self.regex.items():
            try:
                for match in re.findall(regex, str(text)):
                    if key == 'subdomain':
                        if self.base_domain in match.lower() and match.lower() not in self.subdomains:
                            self.subdomains.append(match.lower())
                            cliLogger.success('{} => {}'.format(url, match), bullet='[JS-SUBDOMAIN] ')
                            fileLogger.info('''JS-{},{},{}'''.format(key.upper(), url, match))
                        return
                    cliLogger.success('{} => {}'.format(url, match), bullet='[JS-{}] '.format(key.upper()))
                    fileLogger.info('''JS-{},{},{}'''.format(key.upper(),url, match))
            except Exception as e:
                cliLogger.warning(str(e), bullet='[JS-REGEX-ERROR] ', fg='red')

def main(url, depth=2, timeout=30, conn_timeout=3, proxies=[]):
    cliLogger.info('Launching JS spider agaist {}'.format(url), bullet='[STATUS] ')
    s = JSearch(url, depth, timeout, conn_timeout, proxies)
    s.start()
    while threading.active_count() > 1:
        try:
            sleep(0.5)
        except KeyboardInterrupt:
            cliLogger.warning('Key event detected.', bullet='[CLOSING] ', fg='yellow')
            _exit(0)

if __name__ == '__main__':
    args = argparse.ArgumentParser(description="\t\t{0}".format(argv[0]), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    args.add_argument('-t', dest='timeout', type=int, default=30, help='Spider timeout, 0=None (Default: 30)')
    args.add_argument('-tc', dest='conn_timeout', type=int, default=3, help='Connection timeout')
    args.add_argument('-d', dest='depth', type=int, default=2, help='Spider depth (Default: 2)')
    args.add_argument('-o', dest='outfile', action='store', help='Output to filename to log results')
    args.add_argument('--spider', dest='spider', action='store_true', help='Show all spider results + JavaScript parsing')
    proxy = args.add_mutually_exclusive_group(required=False)
    proxy.add_argument('--proxy', dest='proxy', action='append', default=[], help='Proxy requests (IP:Port)')
    proxy.add_argument('--proxy-file', dest='proxy', default=False, type=lambda x: file_exists(args, x), help='Load proxies from file for rotation')
    args.add_argument(dest='target', nargs='+', help='Target website to crawl')
    args = args.parse_args()

    cliLogger = setup_consoleLogger()
    fileLogger = setup_fileLogger(args.outfile, mode='w')
    fileLogger.info('''Detection,Source URL,Item''')
    cliLogger.info(BANNER)

    for target in ipparser(args.target[0]):
        if not target.startswith(('http://', 'https://')):
            target = "https://"+target
        main(target, args.depth, args.timeout, args.conn_timeout, args.proxy)
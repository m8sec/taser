import threading
from taser import logx
from taser.utils import Timeout
from taser.http.parser import URLParser
from urllib3 import disable_warnings, exceptions
from taser.http import web_request, extract_links, get_statuscode

disable_warnings(exceptions.InsecureRequestWarning)


class Spider(threading.Thread):
    def __init__(self, url, depth=2, timeout=15, conn_timeout=3, headers={}, proxies=[]):
        # Quick spider class to crawl HTML pages and extract links
        threading.Thread.__init__(self)
        self.depth = depth
        self.headers = headers
        self.proxies = proxies
        self.spider_timeout = timeout
        self.conn_timeout = conn_timeout

        self._current_depth = 0
        self._parsed = []
        self.base_domain = URLParser.extract_webdomain(url).lower()
        self.base_subdomain = URLParser.extract_subdomain(url).lower()
        self.init_queue(url)

    def run(self):
        self.spider()

    def init_queue(self, url):
        # init queue and create dict array for each depth
        self._queue = {self._current_depth: [url]}
        for x in range(1, self.depth + 2):
            self._queue[x] = []

    def spider_test(self):
        # Test site is active & init spider variables
        r = web_request(self._queue[0][0], timeout=self.conn_timeout, headers=self.headers, proxies=self.proxies)
        if get_statuscode(r):
            self.init_queue(r.url)
            self.base_domain = URLParser.extract_webdomain(r.request.url).lower()
            self.base_subdomain = URLParser.extract_subdomain(r.request.url).lower()
            return True
        return False

    def spider(self):
        # Start spider timer
        timeout_obj = Timeout(self.spider_timeout)
        if self.spider_timeout > 0 and self.spider_test():
            timeout_obj.start()

        # Start spider
        while self._current_depth <= self.depth:
            if not timeout_obj.running:
                return

            for url in self._queue[self._current_depth]:
                if url not in self._parsed:
                    self._parsed.append(url)
                    self.request(url, self._current_depth+1)
            self._current_depth += 1
        timeout_obj.stop()

    def request(self, url, next_depth):
        # Make url request and pass to parse method
        resp = web_request(url, timeout=self.conn_timeout, headers=self.headers, proxies=self.proxies)
        if get_statuscode(resp):
            self.parse(resp, next_depth)

    def parse(self, resp, next_depth):
        # Determines which pages or items are parsed from the HTTP Response
        if resp.headers['Content-Type'].startswith('text/html'):
            for url in extract_links(resp, mailto=True):
                self.link_handler(url, next_depth)
                self.output_handler(url, resp)

    def safety_check(self, url):
        # Pages to avoid that can adversely impact spider
        if "logout" in URLParser.extract_page(url).lower():
            return False
        elif url.endswith(('.png', '.jpg', '.jpeg', '.gif')):
            return False
        return True

    def link_handler(self, url, next_depth):
        # Filter links before adding to next depth of spider
        if URLParser.extract_subdomain(url).lower() == self.base_subdomain and self.safety_check(url):
            if url not in self._parsed and url not in self._queue[self._current_depth]:
                self._queue[next_depth].append(url)

    def output_handler(self, url, resp):
        # Format links based on type or report to console.
        src_url = resp.url
        subdomain = URLParser.extract_subdomain(url).lower()

        if url.startswith('mailto'):
            logx.bullet('{} => {}'.format(src_url, url), bullet='[EMAIL] ', bullet_fg='green')

        elif self.base_domain in subdomain:
            if self.base_subdomain != subdomain:
                logx.bullet('{} => {}'.format(src_url, url), bullet='[SUBDOMAIN] ', bullet_fg='red')
            else:
                logx.bullet('{} => {}'.format(src_url, url), bullet='[URL] ', bullet_fg='blue')
        else:
            logx.bullet('{} => {}'.format(src_url, url), bullet='[EXTERNAL-URL] ', bullet_fg='purple')

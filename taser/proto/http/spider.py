import threading
from taser import printx
from urllib.parse import urlparse
from taser.utils import TaserTimeout
from urllib3 import disable_warnings, exceptions
from taser.proto.http import web_request, extract_links, extract_webdomain, extract_subdomain, get_statuscode
disable_warnings(exceptions.InsecureRequestWarning)

class Spider(threading.Thread):
    def __init__(self, url, depth=2, timeout=30, conn_timeout=3, headers={}, proxies=[]):
        threading.Thread.__init__(self)
        self.__cur_depth = 1
        self.__url_parsed = []
        self.__url_queue = {}

        self.depth = depth
        self.timeout = timeout
        self.headers = headers
        self.proxies = proxies
        self.conn_timeout = conn_timeout
        self.base_domain = extract_webdomain(url).lower()
        self.base_subdomain = extract_subdomain(url).lower()

        for x in range(1,self.depth+2):
            if x == 1:
                self.__url_queue[x] = [url]
            else:
                self.__url_queue[x] = []

    def run(self):
        self.spider()

    def spider(self):
        spider_timeout = TaserTimeout(self.timeout)
        if self.timeout > 0:
            spider_timeout.start()

        while self.depth >= self.__cur_depth:
            for url in self.__url_queue[self.__cur_depth]:
                if not spider_timeout.running:
                    return
                if url not in self.__url_parsed:
                    self.__url_parsed.append(url)
                    self.crawl(url)
            self.__cur_depth += 1
        spider_timeout.stop()

    def linkModifier(self, url):
        '''
        Modify each URL in web spider before HTTP request
        '''
        return url

    def crawl(self, src_url):
        '''
        Execute web request and send to parser
        '''
        src_url = self.linkModifier(src_url)
        next_depth = (self.__cur_depth+1)
        resp = web_request(src_url, timeout=self.conn_timeout, headers=self.headers, proxies=self.proxies)

        if get_statuscode(resp) != 0:
            self.pageParser(resp, next_depth)

    def pageParser(self, resp, next_depth):
        '''
        Determines which pages or items are parse in HTTP Request. Responsible for calling
        link and output handler methods to continue recursive spider.
        '''
        if resp.headers['Content-Type'].startswith('text/html'):
            for url in extract_links(resp, mailto=True):
                self.linkHandler(url, resp.request.url, next_depth)
                self.outputHandler(url, resp.request.url)

    def linkHandler(self, url, src_url, next_depth):
        '''
        Define which URL's will be added to the next depth array for crawling.
        '''
        if urlparse(url).netloc.lower() == self.base_subdomain:
            if url not in self.__url_parsed and url not in self.__url_queue[self.__cur_depth]:
                self.__url_queue[next_depth].append(url)

    def outputHandler(self, url, src_url):
        '''
        Default method to format links based on type or report to console.
        '''
        subdomain = extract_subdomain(url).lower()

        if url.startswith('mailto'):
            printx.bullet('{} => {}'.format(src_url, url), bullet='[EMAIL] ', bullet_fg='green')

        elif self.base_domain in subdomain:
            if self.base_subdomain != subdomain:
                printx.bullet('{} => {}'.format(src_url, url), bullet='[SUBDOMAIN] ', bullet_fg='red')
            else:
                printx.bullet('{} => {}'.format(src_url, url), bullet='[URL] ', bullet_fg='blue')
        else:
            printx.bullet('{} => {}'.format(src_url, url), bullet='[EXTERNAL-URL] ', bullet_fg='purple')

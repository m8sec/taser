import threading
from taser import printx
from taser.utils import TaserTimeout
from taser.proto.http import web_request, extract_links, extract_webdomain, get_statuscode

class WebSearch(threading.Thread):
    URL = {'google': 'https://www.google.com/search?q={}&num=100&start={}',
           'bing': 'http://www.bing.com/search?q={}&first={}'}

    def __init__(self, search_engine='bing', search_query='', timeout=30, conn_timeout=3, headers={}, proxies=[]):

        threading.Thread.__init__(self)
        self.links   = []
        self.running = True
        self.timeout = timeout
        self.proxies = proxies
        self.headers = headers
        self.conn_timeout = conn_timeout
        self.search_query = search_query
        self.search_engine = search_engine

    def run(self):
        self.search(self.search_engine, self.search_query)

    def search(self, search_engine, search_query):
        search_timeout = TaserTimeout(self.timeout)
        search_timeout.start()

        self.total_links = 0    # Total Links found by search engine
        self.page_links = 0     # Total links found by search engine w/ our domain in URL
        found_links = 0         # Local count to detect when no new links are found

        while search_timeout.running:
            if self.total_links > 0 and found_links == self.page_links:
                search_timeout.stop()
                return self.links
            found_links = self.page_links

            search_url = self.linkModifier(search_engine, search_query)
            resp= web_request(search_url, timeout=self.conn_timeout, headers=self.headers, proxies=self.proxies)
            if get_statuscode(resp) != 0:
                self.pageParser(resp, search_engine, search_query)
        search_timeout.stop()
        return self.links

    def linkModifier(self, search_engine, search_query):
        '''
        Modify search URL prior to GET request
        '''
        return self.URL[search_engine].format(search_query, self.page_links)

    def pageParser(self, resp, search_engine, search_query):
        '''
        Parse search engine results page and increment counts to
        continue recursive search functionality per page.
        '''
        search_domain = extract_webdomain(resp.request.url)
        for url in extract_links(resp, mailto=False, source={'a':'href'}):
            self.total_links += 1
            if extract_webdomain(url) not in [search_domain, 'microsoft.com']:
                self.page_links += 1
                self.linkHander(url, search_engine, search_query)
                self.outputHandler(url, search_engine, search_query)

    def linkHander(self, url, search_engine, search_query):
        '''
        Define how new links will be added to self.links
        '''
        if url not in self.links:
            self.links.append(url)
            printx.bullet(url, bullet='[{}-RESULT] '.format(search_engine.upper()), bullet_fg='green')

    def outputHandler(self, url, search_engine, search_query):
        '''
        Define user output per each new link
        '''
        # Ignored: print statement in linkHandler to avoid processing the same statement.
        return
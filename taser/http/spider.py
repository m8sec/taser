import threading
from random import uniform, shuffle
from time import sleep

from taser import logx
from taser.utils import Timeout
from taser.http.parser import URLParser
from urllib3 import disable_warnings, exceptions
from taser.http import WebSession, extract_links, get_statuscode, random_agent

disable_warnings(exceptions.InsecureRequestWarning)


class Spider(threading.Thread):
    """
    Crawl a site and extract links while keeping request flow consistent.

    The existing constructor shape is preserved. Additional keyword arguments
    are optional and default to conservative behavior.
    """

    BLOCKED_EXTENSIONS = (
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico',
        '.pdf', '.zip', '.tar', '.gz', '.7z',
        '.mp3', '.mp4', '.avi', '.mov', '.mkv',
        '.woff', '.woff2', '.ttf', '.eot',
    )
    BLOCKED_KEYWORDS = ('logout', 'signout', 'logoff', 'delete', 'remove')

    def __init__(self, url, depth=2, timeout=15, conn_timeout=3, headers=None, proxies=None,
                 delay=0.0, jitter=0.0, max_pages=0, follow_redirects=True,
                 randomize_queue=False, preserve_cookies=True):
        # Quick spider class to crawl HTML pages and extract links
        super().__init__()
        self.depth = depth
        self.headers = headers or {}
        self.proxies = proxies or []
        self.spider_timeout = timeout
        self.conn_timeout = conn_timeout
        self.delay = max(0.0, float(delay))
        self.jitter = max(0.0, float(jitter))
        self.max_pages = max(0, int(max_pages))
        self.follow_redirects = follow_redirects
        self.randomize_queue = randomize_queue
        self.preserve_cookies = preserve_cookies

        self._current_depth = 0
        self._parsed = []
        self._parsed_set = set()
        self._queued = set()
        self._lock = threading.Lock()
        self._session = None

        self.headers = self._build_headers(self.headers)
        self.base_domain = URLParser.extract_webdomain(url).lower()
        self.base_subdomain = URLParser.extract_subdomain(url).lower()
        self.init_queue(self.normalize_url(url))

    def _build_headers(self, headers):
        final_headers = dict(headers or {})
        if 'User-Agent' not in final_headers:
            final_headers['User-Agent'] = random_agent()
        final_headers.setdefault('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
        final_headers.setdefault('Accept-Language', 'en-US,en;q=0.9')
        final_headers.setdefault('Connection', 'keep-alive')
        return final_headers

    def run(self):
        self.spider()

    def init_queue(self, url):
        # init queue and create dict array for each depth
        self._current_depth = 0
        self._queue = {self._current_depth: [url]}
        self._queued = {url}
        for x in range(1, self.depth + 2):
            self._queue[x] = []

    def normalize_url(self, url):
        if not url:
            return ''
        if url.startswith(('mailto:', 'javascript:', 'tel:', 'data:')):
            return url
        normalized = URLParser.rm_base_url(url)
        if url.lower().startswith(('http://', 'https://')):
            base_url = URLParser.extract_base_url(url)
            path = normalized.split('#', 1)[0]
            return base_url + path
        return url.split('#', 1)[0]

    def _sleep_between_requests(self):
        pause = self.delay
        if self.jitter > 0:
            pause += uniform(0, self.jitter)
        if pause > 0:
            sleep(pause)

    def _get_session(self):
        if not self._session:
            self._session = WebSession()
        return self._session

    def _request(self, url):
        session = self._get_session()
        cookies = session.session.cookies.get_dict() if self.preserve_cookies else {}
        return session.request(
            url,
            timeout=self.conn_timeout,
            headers=self.headers,
            cookies=cookies,
            proxies=self.proxies,
            redirects=self.follow_redirects,
        )

    def _is_same_domain(self, url):
        subdomain = URLParser.extract_subdomain(url).lower()
        if not subdomain:
            return False
        return subdomain == self.base_subdomain

    def _is_related_domain(self, url):
        subdomain = URLParser.extract_subdomain(url).lower()
        if not subdomain:
            return False
        return subdomain == self.base_domain or subdomain.endswith(f'.{self.base_domain}')

    def spider_test(self):
        # Test site is active & init spider variables
        r = self._request(self._queue[0][0])
        if get_statuscode(r):
            self.init_queue(self.normalize_url(r.url))
            self.base_domain = URLParser.extract_webdomain(r.request.url).lower()
            self.base_subdomain = URLParser.extract_subdomain(r.request.url).lower()
            return True
        return False

    def spider(self):
        # Start spider timer
        timeout_obj = Timeout(self.spider_timeout)
        if self.spider_timeout > 0:
            timeout_obj.start()

        if not self.spider_test():
            if self.spider_timeout > 0:
                timeout_obj.stop()
            self.close()
            return

        # Start spider
        while self._current_depth <= self.depth:
            if self.spider_timeout > 0 and not timeout_obj.running:
                self.close()
                return

            current_urls = list(self._queue[self._current_depth])
            if self.randomize_queue:
                shuffle(current_urls)

            for url in current_urls:
                if self.max_pages and len(self._parsed) >= self.max_pages:
                    timeout_obj.stop()
                    self.close()
                    return

                if url not in self._parsed_set:
                    self._parsed.append(url)
                    self._parsed_set.add(url)
                    self.request(url, self._current_depth + 1)
            self._current_depth += 1
        if self.spider_timeout > 0:
            timeout_obj.stop()
        self.close()

    def request(self, url, next_depth):
        # Make url request and pass to parse method
        self._sleep_between_requests()
        resp = self._request(url)
        if get_statuscode(resp):
            self.parse(resp, next_depth)

    def parse(self, resp, next_depth):
        # Determines which pages or items are parsed from the HTTP Response
        if resp.headers.get('Content-Type', '').startswith('text/html'):
            for url in extract_links(resp, mailto=True):
                self.link_handler(url, next_depth)
                self.output_handler(url, resp)

    def safety_check(self, url):
        # Pages to avoid that can adversely impact spider
        if not url or url.startswith(('mailto:', 'javascript:', 'tel:', 'data:')):
            return False
        path_value = URLParser.extract_path(url).lower()
        page = URLParser.extract_page(url).lower()
        if any(keyword in path_value for keyword in self.BLOCKED_KEYWORDS):
            return False
        if path_value.endswith(self.BLOCKED_EXTENSIONS):
            return False
        return True

    def link_handler(self, url, next_depth):
        # Filter links before adding to next depth of spider
        normalized_url = self.normalize_url(url)
        if not self._is_same_domain(normalized_url) or not self.safety_check(normalized_url):
            return

        if next_depth not in self._queue:
            return

        with self._lock:
            if normalized_url in self._parsed_set or normalized_url in self._queued:
                return
            self._queue[next_depth].append(normalized_url)
            self._queued.add(normalized_url)

    def output_handler(self, url, resp):
        # Format links based on type or report to console.
        src_url = resp.url
        normalized_url = self.normalize_url(url)
        subdomain = URLParser.extract_subdomain(normalized_url).lower()

        if url.startswith('mailto:'):
            logx.bullet('{} => {}'.format(src_url, url), bullet='[EMAIL] ', bullet_fg='green')

        elif self._is_related_domain(normalized_url):
            if self.base_subdomain != subdomain:
                logx.bullet('{} => {}'.format(src_url, normalized_url), bullet='[SUBDOMAIN] ', bullet_fg='red')
            else:
                logx.bullet('{} => {}'.format(src_url, normalized_url), bullet='[URL] ', bullet_fg='blue')
        else:
            logx.bullet('{} => {}'.format(src_url, normalized_url), bullet='[EXTERNAL-URL] ', bullet_fg='purple')

    def close(self):
        if self._session:
            self._session.close()
            self._session = None

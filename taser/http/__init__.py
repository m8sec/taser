import logging
import requests
import warnings
from random import choice
from bs4 import BeautifulSoup
from requests_ntlm import HttpNtlmAuth
from urllib3 import disable_warnings, exceptions
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from taser import LOG
from taser.http.parser import URLParser
from taser.resources.user_agents import USER_AGENTS
from taser.http.browser import web_browser, get_proxy

disable_warnings(exceptions.InsecureRequestWarning)                     # Prevent SSL warnings & cert verification msg
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')   # Hide parser msg
logging.getLogger("charset_normalizer").setLevel(logging.WARNING)       # Hide "encoding detected" msg


class WebSession:
    def __init__(self):
        # Init new session & blank CookieJar
        self.session = requests.Session()

        # Remove Max retries / make room for our own implementation
        adapter = requests.adapters.HTTPAdapter(pool_connections=1, max_retries=0)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def retry(self, url, method, headers, timeout, redirects, max_retries, proxies, **kwargs):
        # Built-in retry does not rotate proxies. Therefore, this custom method
        # pulls a new proxy from the list and retries the current page.
        r = 0
        while r < max_retries:
            r += 1
            LOG.debug('Initiating retry ({}) for: {}'.format(r, url))
            x = self.request(url, method, headers, timeout, redirects, max_retries=0, proxies=proxies, **kwargs)
            if get_statuscode(x): return x
        return False

    def request(self, url, method='GET', headers={}, cookies={}, timeout=4, redirects=True, max_retries=0, proxies=[], **kwargs):
        prox = get_proxy(proxies)
        self.session.cookies.update(cookies)
        self.session.headers.update(headers)
        self.add_header('User-Agent', random_agent()) if "requests" in self.session.headers['User-Agent'] else False

        try:
            req = requests.Request(method, url, **kwargs)
            prep = self.session.prepare_request(req)
            return self.session.send(prep, timeout=timeout, verify=False, allow_redirects=redirects, proxies=prox)
        except requests.exceptions.RequestException as e:
            LOG.debug('Web_Request:Requests::{}'.format(e))
            return self.retry(url, method, headers, timeout, redirects, max_retries, proxies, **kwargs)
        except Exception as e:
            LOG.debug('Web_Request:Generic::{}'.format(e))
        return False

    def reset_headers(self, headers={}):
        self.session.headers.clear()
        self.session.headers.update(headers)

    def add_header(self, key, value):
        self.session.headers.update({key: value})

    def remove_header(self, value):
        self.session.headers.pop(value)

    def close(self):
        self.session.close()


def web_request(url, method='GET', headers={}, cookies={}, timeout=3, redirects=True, max_retries=0, proxies=[], **kwargs):
    # Execute single http request via self handling of WebSession class
    s = WebSession()
    try:
        return s.request(url, method, headers, cookies, timeout, redirects, max_retries, proxies, **kwargs)
    finally:
        s.close()


def download_file(source, output, timeout=5):
    with open(output, 'wb+') as f:
        f.write(web_request(source, timeout=timeout).content)
        f.close()


# HTTP request support functions
def random_agent():
    return choice(USER_AGENTS)


def auth_handler(username, password, auth_type='basic'):
    AUTH = {'basic': HTTPBasicAuth(username, password),
            'ntlm': HttpNtlmAuth(username, password),
            'digest': HTTPDigestAuth(username, password)}
    return AUTH[auth_type]


# Parse response objects w/ built-in error handling
def get_statuscode(resp):
    # Take in requests obj, return status code (0=invalid response)
    try:
        return int(resp.status_code)
    except:
        return 0


def get_title(resp):
    try:
        soup = BeautifulSoup(resp.content, 'lxml')
        return(str(soup.title.string.split(",")[0]).strip().strip('\n'))
    except:
        return "N/A"


def extract_header(header_field, resp):
    try:
        return resp.headers[header_field].strip()
    except:
        return ""


def extract_links(resp, mailto=False, source={'a': 'href', 'script': 'src', 'link': 'href'}):
    links = []
    soup = BeautifulSoup(resp.content, 'lxml')
    for tag in source.keys():
        for link in soup.findAll(tag):
            link = str(link.get(source[tag]))
            if link != "None":
                if link.startswith("/"):
                    links.append(URLParser.rm_slash(resp.url) + link)
                elif mailto and link.startswith('mailto:'):
                    links.append(link)
                elif "://" in link:
                    links.append(link)
                else:
                    links.append(resp.url+link)
    return list(set(links))

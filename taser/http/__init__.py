import urllib
import logging
import requests
import warnings
from random import choice
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from requests_ntlm import HttpNtlmAuth
from urllib3 import disable_warnings, exceptions
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from taser import LOG
from taser.http.parser import URLParser
from taser.resources.user_agents import USER_AGENTS
from taser.utils import unique_values

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

    def retry(self, url, method, headers, cookies, timeout, redirects, max_retries, proxies, raise_errors=False, **kwargs):
        # Built-in retry does not rotate proxies. Therefore, this custom method
        # pulls a new proxy from the list and retries the current page.
        r = 0
        while r < max_retries:
            r += 1
            LOG.debug('Initiating retry ({}) for: {}'.format(r, url))
            x = self.request(
                url,
                method,
                headers,
                cookies,
                timeout,
                redirects,
                max_retries=0,
                proxies=proxies,
                raise_errors=raise_errors,
                **kwargs,
            )
            if get_statuscode(x): return x
        return False

    def request(self, url, method='GET', headers=None, cookies=None, timeout=4, redirects=True, max_retries=0,
                proxies=None, raise_errors=False, **kwargs):
        headers = headers or {}
        cookies = cookies or {}
        proxies = proxies or []
        prox = get_proxy(proxies)
        self.session.cookies.update(cookies)
        self.session.headers.update(headers)
        user_agent = self.session.headers.get('User-Agent', '')
        if "requests" in user_agent:
            self.add_header('User-Agent', random_agent())

        try:
            req = requests.Request(method, url, **kwargs)
            prep = self.session.prepare_request(req)
            return self.session.send(prep, timeout=timeout, verify=False, allow_redirects=redirects, proxies=prox)
        except requests.exceptions.RequestException as e:
            LOG.debug('Web_Request:Requests::{}'.format(e))
            if raise_errors:
                raise
            return self.retry(url, method, headers, cookies, timeout, redirects, max_retries, proxies, raise_errors=raise_errors, **kwargs)
        except Exception as e:
            LOG.debug('Web_Request:Generic::{}'.format(e))
            if raise_errors:
                raise
        return False

    def reset_headers(self, headers=None):
        self.session.headers.clear()
        self.session.headers.update(headers or {})

    def add_header(self, key, value):
        self.session.headers.update({key: value})

    def remove_header(self, value):
        self.session.headers.pop(value)

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def web_request(url, method='GET', headers=None, cookies=None, timeout=3, redirects=True, max_retries=0,
                proxies=None, raise_errors=False, **kwargs):
    # Execute single http request via self handling of WebSession class
    with WebSession() as session:
        return session.request(
            url,
            method,
            headers,
            cookies,
            timeout,
            redirects,
            max_retries,
            proxies,
            raise_errors=raise_errors,
            **kwargs,
        )


def download_file(source, output, timeout=5, raise_errors=False):
    resp = web_request(source, timeout=timeout, raise_errors=raise_errors)
    if not resp:
        return False
    with open(output, 'wb+') as f:
        f.write(resp.content)
    return True


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


def extract_links(resp, mailto=False, source=None):
    source = source or {'a': 'href', 'script': 'src', 'link': 'href'}
    links = []
    soup = BeautifulSoup(resp.content, 'lxml')
    base_url = getattr(resp, 'url', '')

    for tag, attribute in source.items():
        for link in soup.find_all(tag):
            href = link.get(attribute)
            if href is None:
                continue

            href = str(href).strip()
            if not href:
                continue

            if href.startswith('mailto:'):
                if mailto:
                    links.append(href)
                continue

            links.append(urljoin(base_url, href))

    return unique_values(links)

def get_proxy(proxies=False, system=False):
    # Take in list value and return random proxy formated for python-requests
    if system:
        return urllib.request.getproxies()
    elif proxies:
        tmp = choice(proxies)
        return {"http": tmp, "https": tmp}
    return {}

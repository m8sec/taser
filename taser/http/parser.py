from dataclasses import dataclass
from argparse import Namespace
from urllib.parse import parse_qs, urlparse
from taser.utils import ipv4check


@dataclass(frozen=True)
class ParsedURL:
    domain: str
    subdomain: str
    path: str
    page: str
    dir: str
    params: str
    proto: str
    tag: str
    extension: str
    port: int


class URLParser:
    MULTI_PART_TLDS = [
        "co.uk", "org.uk", "gov.uk", "ac.uk",
        "com.au", "net.au", "org.au",
        "co.nz", "net.nz", "org.nz",
    ]

    @classmethod
    def read(cls, data):
        parsed = cls.read_structured(data)
        return Namespace(**parsed.__dict__)

    @classmethod
    def read_structured(cls, data):
        p = urlparse(data)
        return ParsedURL(
            domain=cls.extract_webdomain(data),
            subdomain=p.netloc,
            path=cls.extract_path(data),
            page=cls.extract_page(data),
            dir=cls.extract_dir(data),
            params=p.query,
            proto=p.scheme,
            tag=p.fragment,
            extension=cls.extract_extension(data),
            port=cls.extract_port(data),
        )

    @staticmethod
    def extract_webdomain(url):
        # Extract the netloc part of the URL
        netloc = urlparse(url).netloc
        if ':' in netloc:
            netloc = netloc.split(':')[0]

        if ipv4check(netloc):
            return netloc

        parts = netloc.split('.')
        if len(parts) > 2 and '.'.join(parts[-2:]) in URLParser.MULTI_PART_TLDS:
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])

    @staticmethod
    def extract_subdomain(url):
        # https://test.example.com/login --> test.example.com
        sub = urlparse(url).netloc
        return sub.split(':')[0] if ':' in sub else sub

    @staticmethod
    def extract_port(url, default=443):
        # Extract subdomain without stripping port
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc

        if ':' in netloc:
            return int(netloc.split(':')[-1])
        elif url.startswith('https://'):
            return 443
        elif url.startswith('http://'):
            return 80
        return default

    @staticmethod
    def extract_path(url):
        # https://test.com/admin/01/index.php --> /admin/01/index.php
        p = urlparse(url).path
        return p if p else '/'

    @staticmethod
    def extract_base_url(url):
        # https://test.example.com/admin/logon.php = https://test.example.com
        x = urlparse(url)
        return x.scheme + "://" + x.netloc

    @staticmethod
    def extract_page(url):
        # https://test.com/admin/login.php --> login.php
        p = urlparse(url).path.split('/')[-1]
        return p if p.find('.') > -1 else ''

    @classmethod
    def extract_extension(cls, url):
        # https://test.com/admin/login.php --> php
        p = cls.extract_page(url)
        p = p.split('/')[-1]
        return p.split('.')[-1] if p.find('.') > -1 and p.index('.') > 0 else ''

    @classmethod
    def extract_dir(cls, url):
        # https://test.com/admin/login.php --> /admin/
        path_value = cls.extract_path(url)
        if path_value == '/':
            return '/'
        if path_value.endswith('/'):
            return path_value
        split_path = path_value.rsplit('/', 1)[0]
        return split_path if split_path.startswith('/') else f'/{split_path}'

    @staticmethod
    def remove_page(url):
        # https://test.com/admin/login.php --> https://test.com/admin/
        u = urlparse(url)
        p = u.path.split('/')[-1]
        pwd = (u.scheme+'://'+u.netloc+'/'.join(u.path.split('/')[:-1])) if p.find('.') > -1 else url
        return URLParser.url_format(pwd)

    @staticmethod
    def rm_slash(url):
        # http://test.com/admin/ --> http://test.com/admin
        return url[:-1] if url.endswith('/') else url

    @staticmethod
    def rm_base_url(url):
        # https://test.com/admin?abc=1 --> /admin?abc=1
        parsed_url = urlparse(url)
        path = parsed_url.path or '/'
        if parsed_url.query:
            path += '?' + parsed_url.query
        if parsed_url.fragment:
            path += '#' + parsed_url.fragment
        return path

    @staticmethod
    def url_format(url):
        # Append appropriate "/" characters to URL - if needed
        # https://test.com/admin --> https://test.com/admin/
        u = urlparse(url)
        return url if any(["." in u.path.split('/')[-1], url.endswith('/'), u.params, u.query]) else url+"/"

    @staticmethod
    def target2url(data, protocol='https'):
        # test.com --> https://test.com/
        url = data if data.lower().startswith(('http://', 'https://')) else ''.join([protocol, '://', data])
        return URLParser.url_format(url)


class RequestParser:
    """
    Parse a raw HTTP request string into structured fields.

    Existing attributes such as ``method``, ``page``, ``headers``, ``data``,
    and ``url`` are preserved for compatibility. Additional derived attributes
    are populated to make the parser useful as a general request abstraction.
    """

    def __init__(self, raw_request, protocol='https'):
        self.raw = self._normalize_raw_request(raw_request)
        self.protocol = protocol

        self.is_valid = False
        self.error = ''

        self.method = ''
        self.target = ''
        self.page = ''
        self.raw_version = ''
        self.http_version = ''
        self.headers = {}
        self.header_items = []
        self.data = ''
        self.body = ''
        self.host = ''
        self.port = None
        self.scheme = protocol
        self.path = ''
        self.query = ''
        self.query_params = {}
        self.fragment = ''
        self.base_url = ''
        self.content_length = 0

        self.parse()
        self.url = self.build_url()

    @staticmethod
    def _normalize_raw_request(raw_request):
        if isinstance(raw_request, bytes):
            raw_request = raw_request.decode('iso-8859-1', errors='replace')
        return str(raw_request).replace('\r\n', '\n').replace('\r', '\n')

    @staticmethod
    def _split_header_line(line):
        key, sep, value = line.partition(':')
        if not key or not sep:
            return '', ''
        return key.strip(), value.strip()

    def get_header(self, key, default=''):
        return self.headers.get(key, default)

    def build_url(self):
        if not self.is_valid:
            return ''

        if self.target.lower().startswith(('http://', 'https://')):
            return self.target

        if not self.host:
            return ''

        return f'{self.scheme}://{self.host}{self.page}'

    def _parse_target(self):
        parsed = urlparse(self.target)

        if self.target.lower().startswith(('http://', 'https://')):
            self.scheme = parsed.scheme or self.protocol
            self.host = parsed.netloc
            self.path = parsed.path or '/'
            self.query = parsed.query
            self.fragment = parsed.fragment
            self.page = self.path
        else:
            self.scheme = self.protocol
            self.host = self.get_header('Host', '')
            self.path = parsed.path or self.target or '/'
            self.query = parsed.query
            self.fragment = parsed.fragment
            self.page = self.path

        if self.query:
            self.page = f'{self.page}?{self.query}'
        if self.fragment:
            self.page = f'{self.page}#{self.fragment}'

        self.query_params = parse_qs(self.query, keep_blank_values=True) if self.query else {}
        self.base_url = f'{self.scheme}://{self.host}' if self.host else ''

        if self.host:
            host_parsed = urlparse(f'{self.scheme}://{self.host}')
            self.port = host_parsed.port or (443 if self.scheme == 'https' else 80)

    def parse(self):
        raw_input = self.raw.splitlines()
        if not raw_input:
            self.error = 'Empty request'
            return

        request_line = raw_input[0].strip().split(maxsplit=2)
        if len(request_line) != 3:
            self.error = 'Invalid request line'
            return
        self.method, self.target, self.raw_version = request_line
        self.http_version = self.raw_version.split('/')[-1]

        body_lines = []
        in_body = False

        for line in raw_input[1:]:
            if in_body:
                body_lines.append(line)
                continue

            if line == '':
                in_body = True
                continue

            key, value = self._split_header_line(line)
            if key:
                self.headers[key] = value
                self.header_items.append((key, value))

        self.data = '\n'.join(body_lines)
        self.body = self.data
        self._parse_target()

        try:
            self.content_length = int(self.get_header('Content-Length', '0') or 0)
        except ValueError:
            self.content_length = 0

        self.is_valid = True

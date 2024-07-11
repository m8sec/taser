from argparse import Namespace
from tldextract import extract
from urllib.parse import urlparse
from taser.utils import ipcheck


class URLParser:
    @classmethod
    def read(cls, data):
        p = urlparse(data)
        return Namespace(
            domain=cls.extract_webdomain(data),
            subdomain=p.netloc,
            path=cls.extract_path(data),
            page=cls.extract_page(data),
            dir=cls.extract_dir(data),
            params=p.query,
            proto=p.scheme,
            tag=p.fragment,
            extension=cls.extract_extension(data),
            port=cls.extract_port(data)
        )

    @staticmethod
    def extract_webdomain(url):
        # test.example.com --> example.com
        x = extract(url)
        return x.domain if ipcheck(x.domain) else '.'.join([x.domain, x.suffix])

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
        p = cls.extract_path(url).split('/')
        return '/'.join(p[:-1])

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
        path_query_fragment = parsed_url.path + parsed_url.query + parsed_url.fragment
        return path_query_fragment if path_query_fragment else '/'

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
    # Take in raw request and format (work in progress)
    def __init__(self, raw_request, protocol='https'):
        self.raw = raw_request
        self.protocol = protocol

        self.method = ''
        self.page = ''
        self.raw_version = ''
        self.http_version = ''
        self.headers = {}
        self.data = ''

        self.parse()

        try:
            self.url = self.protocol + '://' + self.headers['Host'] + self.page
        except Exception as e:
            self.url = ''

    def parse(self):
        blank_line = False
        raw_input = self.raw.splitlines()

        self.method, self.page, self.raw_version = raw_input[0].split(' ')
        self.http_version = self.raw_version.split('/')[-1]

        for line in raw_input[1:]:
            if line:
                if blank_line:
                    self.data += line
                    return

                else:
                    k, v = line.strip().split(': ')
                    self.headers[k] = v
            else:
                blank_line = True

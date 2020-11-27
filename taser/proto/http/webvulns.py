from random import choice
from taser.proto.tcp import PySocks3
from taser.utils import gen_random_string
from taser.proto.http import web_request, USERAGENTS, extract_header, rm_slash, extract_subdomain

class WebVulns():
    '''
    Collection of Python methods that can be used to check
    for common web vulnerabilities.
    (experimental, under in active development)
    '''
    @staticmethod
    def webdav_check(url):
        if web_request(url, 'PROPFIND').status_code == 207:
            return True
        return False

    @staticmethod
    def putFile(url, timeout=4, data='TASER', data_ext=".txt", headers={}, content_type="text/plain", proxies=[], debug=False):
        upload_file = gen_random_string(5) + data_ext
        target_url = rm_slash(url) + "/" + upload_file
        h = {
                    'Host': extract_subdomain(url),
                    'Content-Type': content_type,
                    'Content-Length': str(len(data)),
                    'Connection': 'close'
                }
        for k,v in headers.items():
            h[k] = v
        r1 = web_request(target_url, method='PUT', headers=h, data=data, timeout=timeout, proxies=proxies, debug=debug)
        # Check via status code
        if r1 and r1.status_code in [200,204,202]:
            # Verify
            r2 = web_request(target_url, method='GET', timeout=timeout, proxies=proxies, debug=debug)
            if r2 and r2.status_code == 200 and data in r2.text:
                return upload_file
        return False

    @staticmethod
    def deleteFile(url, filename, timeout=4, proxies=[], headers={}, debug=False):
        target_url = rm_slash(url) + "/" + filename
        h = {
            'Host': extract_subdomain(url),
            'Connection': 'close'
        }
        for k,v in headers.items():
            h[k] = v
        r = web_request(target_url, method='DELETE', headers=h, timeout=timeout, proxies=proxies, debug=debug)
        if r and r.status_code in [200, 204, 202]:
            return True
        return False

    @staticmethod
    def shellshock(url, target="User-Agent", timeout=5, proxies=[], debug=False):
        header = {target: "() { :; }; echo; echo; /bin/bash -c 'a=$((74*80*1103)) && echo Test-$a'"}
        resp = web_request(url, headers=header, timeout=timeout, proxies=proxies, debug=debug)
        if resp and "Test-6529760" in resp.text:
            return True
        return True

    @staticmethod
    def cors_check(url, test_addr='example123abc.com', timeout=5, proxies=[], debug=False):
        data = {}
        header = {
                  'User-Agent': choice(USERAGENTS),
                  'Referer'   : url,
                  'Origin'    : test_addr
                 }
        try:
            resp = web_request(url, header, timeout=timeout, proxies=proxies, debug=debug)
            cors = extract_header('Access-Control-Allow-Origin', resp)
            if cors in [test_addr, '*']:
                data['Access-Control-Allow-Origin'] = cors
                for key,val in resp.headers.items():
                    if key.startswith('Access-Control-Allow') and key != 'Access-Control-Allow-Origin':
                        data[key] = val.strip()
        except:
            return False
        return data
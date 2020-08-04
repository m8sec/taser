# TESTING ONLY
import sys
sys.path.append('..')

from time import sleep
from taser.proto.http import web_request

# Site to simply reflect the requesting ip address
target = 'http://ident.me'

# proxy_list
proxies = [
    'socks4://119.235.50.26:4145',
    'socks4://103.107.68.33:5430',
    'socks4://103.211.8.149:52616',
    'socks5://badproxy-abc123.com',
]

for x in range(0,3):
    print('\nSending Request')
    r = web_request(target, proxies=proxies, headers={'X-Forwarded-For':'127.0.0.1'}, max_retries=1, timeout=3, debug=True)
    if r:
        print(r.text)
    else:
        print('Error: No response')
    sleep(1)
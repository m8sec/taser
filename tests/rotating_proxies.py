# TESTING ONLY
import sys
sys.path.append('..')
###

from time import sleep
from taser.proto.http import web_request

# Site to simply reflect the requesting ip address
target = 'http://ident.me'

# proxy_list
proxies = [
    'socks4://proxy.com:52616',
    'socks5://proxy.com:9000',
]

for x in range(0,3):
    print('\nSending Request')
    r = web_request(target, proxies=proxies, headers={'X-Forwarded-For':'127.0.0.1'}, max_retries=1, timeout=3)
    if r:
        print(r.text)
    else:
        print('Error: No response')
    sleep(1)

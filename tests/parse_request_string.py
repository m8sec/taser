# TESTING ONLY
import sys
sys.path.append('..')
###

from taser.http.parse import RequestParser

raw_req = '''GET /test_page HTTP/1.1
Host: www.yahoo.com
Connection: Keep-alive

{data=test123}
'''

s = RequestParser(raw_req)
print('\nurl: {}'.format(s.url))
print('protocol: {}'.format(s.protocol))
print('method: {}'.format(s.method))
print('page: {}'.format(s.page))
print('raw_version: {}'.format(s.raw_version))
print('http_version: {}'.format(s.http_version))

print('\nheaders:')
for k, v in s.headers.items():
    print('  |_ {} : {}'.format(k,v))

print('\ndata:\n  {}\n'.format(s.data))

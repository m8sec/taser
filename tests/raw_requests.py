# TESTING ONLY
import sys
sys.path.append('..')

from taser.proto.http import exec_rawRequest

req = '''GET / HTTP/1.1
Host: www.yahoo.com
'''

resp = exec_rawRequest(req, debug=True)
print("[+] ", resp.url, " --> ", resp.status_code)
for x in resp.request.headers:
    print(" "*8, x, ": ", resp.request.headers[x])
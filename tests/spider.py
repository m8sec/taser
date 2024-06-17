# TESTING ONLY
import sys
sys.path.append('..')
###
import sys
from taser.http.spider import Spider

url = sys.argv[1]
s = Spider(url, depth=2, timeout=30, conn_timeout=3, headers={}, proxies=[])

# Start spider as thread
#s.start()

# Start in main
s.spider()

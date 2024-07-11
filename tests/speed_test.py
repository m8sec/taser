# TESTING ONLY
import sys
sys.path.append('..')
###

import sys
from taser.http import web_request
from datetime import datetime

# Setup
url = sys.argv[1]
start_timer = datetime.now()

# Make Request
resp = web_request(url)
print('{} - {}'.format(url, resp.status_code))

# Stop timer
stop_timer = datetime.now()
total_time = stop_timer - start_timer
req_time = resp.elapsed.total_seconds()
exec_time = total_time.total_seconds() - float(req_time)

# Output
print('Total time {}'.format(exec_time))
print('  |_ request time: {}'.format(req_time))
print('  |_ Exec time: {}'.format(exec_time))

# TESTING ONLY
import sys
sys.path.append('..')

import os
import logging
from taser.logx import setup_consoleLogger, setup_fileLogger, TaserAdapter

x = setup_consoleLogger()
x.write('\nLog level test:')
x.critical('[!] Console log: Critical {}'.format(logging.CRITICAL))
x.warning('Console log: Warning {}'.format(logging.WARNING))
x.info('console log: Info {}'.format(logging.INFO))
x.debug('Console log: Debug {}'.format(logging.DEBUG))

x.write('\nTaser adapter test:')
x.write('[*] write')
x.info('info')
x.success('success')
x.fail('fail')
x.status('status')
x.warning('warning')
x.debug('debug')
x.critical('')

x.write('\nTaser file handler test:')
y = setup_fileLogger(False)
y.info('Log to file test, no filename')
y.debug('Log to file test, no filename')

z = setup_fileLogger('log_test.txt')
z.info('Log to file test, no filename')
z.debug('Log to file test, no filename')

if os.path.exists('log_test.txt'):
    x.info('Log file creation successful!')
    os.remove('log_test.txt')
else:
    x.warning('Failed to create log file.')
# TESTING ONLY
import sys
sys.path.append('..')

from os import path
from taser.db.sqlite import SQLiteDB
from taser.logx import setup_consoleLogger, setup_dbLogger

'''
Test custom Handler and Adapter to use the logging
library to perform write queries to a DB.
'''

# Create CLI logger for console output
cli = setup_consoleLogger()

# Setup DB class obj & connect
test_db = './taser_test_only.sqlite'
x = SQLiteDB(dbname=test_db)
x.connect(x.dbname)

db = setup_dbLogger(x)
# Can only perform "write" queries
db.query('CREATE TABLE TEST (ID INTEGER PRIMARY KEY AUTOINCREMENT);')
db.query('INSERT INTO TEST (ID) VALUES (1);')

if path.exists(test_db):
    cli.success('DB file created.')
    if x.exec(x.con, 'SELECT * FROM TEST;'):
        cli.success('Query executed.')
    else:
        cli.fail('DB file or query not found.')

x.close()
x.delete()
if not path.exists(test_db):
    cli.info('DB file removed.')
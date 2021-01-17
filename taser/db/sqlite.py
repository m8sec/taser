from os import remove
from sqlite3 import connect

'''
Cursor and commit currently called during exec to prevent end-dev
from worrying about try/except/finally: db.close() or handling
Keyboardinterrupts, resulting in possible data loss...

Open to alternatives here :)
'''

class SQLiteDB():
    def __init__(self, dbname='taser.sqlite'):
        self.timeout = 3
        self.dbname = dbname
        self.connect()

    def connect(self):
        self.con = connect(self.dbname, timeout=self.timeout, check_same_thread=False)

    def exec(self, query):
        if not self.con:
            raise Exception('No database connection')
        cur = self.con.cursor()
        cur.execute(query)
        data = cur.fetchall()
        self.con.commit()
        cur.close()
        return data

    def delete(self):
        self.close()
        remove(self.dbname)

    def close(self):
        try:
            self.con.close()
        except:
            pass
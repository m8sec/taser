import MySQLdb

class MySQLDB():
    def __init__(self,username, password, host='localhost', port=3306):
        self.host = host
        self.port = port

        self.username = username
        self.password = password

        self.conn_timeout = 3
        self.query_timeout = 15


    def connect(self, dbname):
        try:
            if dbname:
                self.con = MySQLdb.connect(host=self.host, port=self.port, user=self.username, db=dbname,
                                      password=self.password, connect_timeout=self.conn_timeout)
            else:
                self.con = MySQLdb.connect(host=self.host, port=self.port, user=self.username,
                                      password=self.password, connect_timeout=self.conn_timeout)
            self.con.query_timeout = self.query_timeout
            return True
        except:
            return False

    def exec(self, con, query):
        cur = con.cursor()
        cur.execute(query)
        data = cur.fetchall()
        cur.close()
        con.commit()
        return data

    def close(self):
        self.con.close()
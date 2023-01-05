import ftplib

class FTP:
    @staticmethod
    def login(target, port, username, password, time_out, ssl=False, verbose=False):
        try:
            ftp = ftplib.FTP(timeout=time_out)
            ftp.connect(target, port)
            ftp.login(username, password)
            if ssl:
                ftp.auth()
            return ftp
        except Exception as e:
            if verbose:
                print('[!] Error:ftp_login:: {}'.format(str(e)))
        return False

    @staticmethod
    def list_dir(ftp_con, dir=False):
        data = []
        ftp_con.set_pasv(True)
        if dir:
            ftp_con.cwd(dir)
        ftp_con.dir(data.append)
        return data

    @staticmethod
    def quit(ftp_con):
        try:
            ftp_con.quit()
        except:
            pass

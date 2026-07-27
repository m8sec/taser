import ftplib
from taser import LOG


class FTP:
    @staticmethod
    def login(target, port, username, password, time_out, ssl=False, verbose=False, raise_errors=False):
        try:
            ftp = ftplib.FTP_TLS(timeout=time_out) if ssl else ftplib.FTP(timeout=time_out)
            ftp.connect(target, port)
            if ssl:
                ftp.auth()
            ftp.login(username, password)
            if ssl:
                ftp.prot_p()
            return ftp
        except Exception as e:
            LOG.debug('Error:ftp_login:: {}'.format(str(e)))
            if raise_errors:
                raise
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
        except Exception:
            pass

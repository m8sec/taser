import ssl
import socket
import logging


class PySocks3:
    # Helper class for encoding/decoding in Python3's socket
    # implementation. Also supports SSL wrapped sockets.
    def __init__(self):
        self.sock = False

    def connect(self, target, port, timeout=3, use_ssl=False, ssl_version=False):
        self.set_timeout(timeout)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((target, int(port)))

        if use_ssl and ssl_version:
            set_ssl_version(ssl_version)

        elif use_ssl:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.sock = ctx.wrap_socket(s)
        return self

    def set_ssl_version(self, ssl_version):
        self.sock = ssl.wrap_socket(self.sock, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl_version)

    def set_timeout(self, timeout):
        socket.setdefaulttimeout(timeout)

    def close(self):
        self.sock.close()
        del self.sock

    def send(self, msg, max_retries=1):
        try:
            self.sock.sendall(msg.encode('utf-8'))
        except socket.error as e:
            if max_retries > 0:
                return self.resend(msg, max_retries)
        return True

    def resend(self, msg, max_retries):
        retry = 0
        while retry < max_retries:
            x = self.resend(self.sock, msg, 0)
            if x:
                return True
            retry += 1
        return False

    def recv(self):
        buff_size = 1024
        data = b''
        try:
            while True:
                new =self.sock.recv(buff_size)
                data += new
                if len(str(new)) < buff_size:
                    return data.decode('utf-8').rstrip('\n')
        except:
            return data.decode('utf-8').rstrip('\n')


def get_banner(target, port, timeout=3, use_ssl=False):
    banner = False
    try:
        s = PySocks3().connect(target, port, timeout=timeout, use_ssl=use_ssl)
        banner = s.recv().strip()
        banner = banner.strip("\n")
        s.close()
    except Exception as e:
        logging.debug("TCP:Get_Banner::{}".format(e))
    return banner

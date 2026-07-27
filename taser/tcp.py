import ssl
import socket
from taser import LOG


class PySocks3:
    # Helper class for encoding/decoding in Python3's socket
    # implementation. Also supports SSL wrapped sockets.
    def __init__(self):
        self.sock = False

    def connect(self, target, port, timeout=3, use_ssl=False, raise_errors=False):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((target, int(port)))
            if use_ssl:
                ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                self.sock = ctx.wrap_socket(self.sock, server_hostname=target, do_handshake_on_connect=True)
            return self
        except Exception:
            self.close()
            if raise_errors:
                raise
            return self

    def set_timeout(self, timeout):
        if self.sock:
            self.sock.settimeout(timeout)

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = False

    def send(self, msg):
        try:
            self.sock.sendall(msg.encode('utf-8'))
        except Exception:
            return False
        return True

    def recv(self, buff_size=2048, raise_errors=False):
        data = b''
        try:
            while True:
                new = self.sock.recv(buff_size)
                data += new
                if not new or len(new) < buff_size:
                    return data.decode('utf-8').rstrip('\n')
        except Exception:
            if raise_errors:
                raise
            return data.decode('utf-8').rstrip('\n')


def get_banner(target, port, timeout=3, use_ssl=False, raise_errors=False):
    banner = False
    try:
        s = PySocks3().connect(target, port, timeout=timeout, use_ssl=use_ssl, raise_errors=raise_errors)
        if not s.sock:
            return banner
        banner = s.recv(raise_errors=raise_errors).strip()
        banner = banner.strip("\n")
        s.close()
    except Exception as e:
        LOG.debug("TCP:Get_Banner::{}".format(e))
        if raise_errors:
            raise
    return banner

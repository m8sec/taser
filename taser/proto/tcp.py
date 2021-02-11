import ssl
import socket

class PySocks3():
    '''
    Limited implementation of the Sockets library with
    Python3 support for SSL, Encoding and Decoding.
    '''
    def connect(self, target, port, SSL=False, timeout=3, ssl_version=ssl.PROTOCOL_SSLv23, address_family=socket.AF_INET, socket_type=socket.SOCK_STREAM):
        self.settimeout(timeout)
        self.sock = socket.socket(address_family, socket_type)
        if SSL:
            try:
                self.sock = ssl.wrap_socket(self.sock, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl_version)
            except:
                self.sock = ssl.wrap_socket(self.sock, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLSv1_2)
        self.sock.connect((target, int(port)))
        return self

    def settimeout(self, timeout):
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

def get_banner(target, port, ssl=False, timeout=3):
    banner = False
    try:
        s = PySocks3().connect(target, port, SSL=ssl, timeout=timeout)
        banner = s.recv().strip()
        banner = banner.strip("\n")
        s.close()
    except:
        return False
    return banner
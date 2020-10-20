import ssl
import socket

# Python3 Socket Support Functions
def create_socket(target, port, SSL=False, timeout=3, ssl_version=ssl.PROTOCOL_SSLv23):
    socket.setdefaulttimeout(timeout)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if SSL:
        try:
            sock = ssl.wrap_socket(sock, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl_version)
        except:
            sock = ssl.wrap_socket(sock, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLSv1_2)
    sock.connect((target, int(port)))
    return sock

def sock_close(sock):
    sock.close()
    del sock

def sock_send(sock, msg, max_retries=1):
    try:
        sock.sendall(msg.encode('utf-8'))
    except socket.error as e:
        if max_retries > 0:
            return sock_retry(sock, msg, max_retries)
    return True

def sock_retry(sock, msg, max_retries):
    retry = 0
    while retry < max_retries:
        x = sock_retry(sock, msg, 0)
        if x:
            return True
        retry += 1
    return False

def sock_recv(sock):
    buff_size = 1024
    data = b''
    try:
        while True:
            new =sock.recv(buff_size)
            data += new
            if len(str(new)) < buff_size:
                return data.decode('utf-8').rstrip('\n')
    except:
        return data.decode('utf-8').rstrip('\n')

def get_banner(target, port, ssl=False, timeout=3):
    banner = ''
    sock = create_socket(target, port, SSL=ssl, timeout=timeout)
    banner = sock_recv(sock)
    if banner[-1] == "\n":
        banner=banner[:-1]
    sock_close(sock)
    return banner.strip()
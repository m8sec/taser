import ssl
import socket
import socketserver
from typing import Callable
from taser import LOG


SOCKS5_VERSION = b"\x05"
SOCKS5_NOAUTH = b"\x00"
SOCKS5_CONNECT = b"\x01"
SOCKS5_ATYP_IPV4 = b"\x01"
SOCKS5_ATYP_DOMAIN = b"\x03"
SOCKS5_ATYP_IPV6 = b"\x04"


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


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed before receiving expected data")
        data += chunk
    return data


def negotiate_socks5_connect(sock, target_host, target_port):
    sock.sendall(SOCKS5_VERSION + b"\x01" + SOCKS5_NOAUTH)
    method_reply = recv_exact(sock, 2)
    if method_reply != SOCKS5_VERSION + SOCKS5_NOAUTH:
        raise ConnectionError("proxy does not allow unauthenticated SOCKS5 sessions")

    host_bytes = target_host.encode("idna")
    if len(host_bytes) > 255:
        raise ValueError("target host is too long for SOCKS5 domain mode")

    request = (
        SOCKS5_VERSION
        + SOCKS5_CONNECT
        + b"\x00"
        + SOCKS5_ATYP_DOMAIN
        + bytes([len(host_bytes)])
        + host_bytes
        + int(target_port).to_bytes(2, "big")
    )
    sock.sendall(request)

    header = recv_exact(sock, 4)
    if header[0:1] != SOCKS5_VERSION:
        raise ConnectionError("proxy returned an invalid SOCKS version")
    if header[1] != 0x00:
        raise ConnectionError("proxy CONNECT request failed with code {}".format(header[1]))

    atyp = header[3:4]
    if atyp == SOCKS5_ATYP_IPV4:
        recv_exact(sock, 6)
    elif atyp == SOCKS5_ATYP_DOMAIN:
        domain_len = recv_exact(sock, 1)[0]
        recv_exact(sock, domain_len + 2)
    elif atyp == SOCKS5_ATYP_IPV6:
        recv_exact(sock, 18)
    else:
        raise ConnectionError("proxy returned unknown bind address type {}".format(atyp.hex()))
    return sock


def open_socks5_connection(proxy_host, proxy_port, target_host, target_port, timeout=5):
    sock = socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout)
    sock.settimeout(timeout)
    try:
        return negotiate_socks5_connect(sock, target_host, target_port)
    except Exception:
        sock.close()
        raise


def build_http_text_response(message, status="200 OK", content_type="text/plain; charset=utf-8"):
    payload = message.encode("utf-8", errors="replace")
    response = [
        "HTTP/1.0 {}".format(status),
        "Content-Type: {}".format(content_type),
        "Content-Length: {}".format(len(payload)),
        "",
        "",
    ]
    return "\r\n".join(response).encode("ascii") + payload


def create_tcp_handler(responder: Callable[[bytes, tuple[str, int]], bytes]):
    class TCPResponderHandler(socketserver.BaseRequestHandler):
        def handle(self):
            data = self.request.recv(4096)
            if not data:
                return
            response = responder(data, self.client_address)
            if response:
                self.request.sendall(response)

    return TCPResponderHandler


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCPResponseServer:
    def __init__(self, host, port, responder):
        self.host = host
        self.port = port
        self.responder = responder
        self._server = ThreadedTCPServer((self.host, self.port), create_tcp_handler(self.responder))

    @property
    def server_address(self):
        return self._server.server_address

    def serve_forever(self):
        self._server.serve_forever()

    def shutdown(self):
        self._server.shutdown()

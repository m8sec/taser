"""Reusable helpers for the reverse SOCKS example scripts."""

from __future__ import annotations

import json
import socket
import threading
from dataclasses import dataclass, field


MAGIC_PREFIX = b"SPROX1 "
SOCKS_VERSION = 0x05
SOCKS_METHOD_NOAUTH = 0x00
SOCKS_METHOD_REJECT = 0xFF
SOCKS_CMD_CONNECT = 0x01
SOCKS_ATYP_IPV4 = 0x01
SOCKS_ATYP_DOMAIN = 0x03
SOCKS_ATYP_IPV6 = 0x04
SOCKS_REPLY_SUCCESS = 0x00
SOCKS_REPLY_GENERAL_FAILURE = 0x01
SOCKS_REPLY_COMMAND_UNSUPPORTED = 0x07
SOCKS_REPLY_ADDRESS_UNSUPPORTED = 0x08


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data


def read_frame(fileobj):
    line = fileobj.readline()
    if not line:
        raise EOFError("connection closed")
    return json.loads(line.decode("utf-8"))


def send_frame(sock, payload, lock=None):
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    if lock is None:
        sock.sendall(data)
        return
    with lock:
        sock.sendall(data)


def build_client_hello():
    payload = {"role": "client"}
    return MAGIC_PREFIX + json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"


def parse_client_hello(line):
    if not line.startswith(MAGIC_PREFIX):
        raise ValueError("invalid client hello prefix")
    payload = json.loads(line[len(MAGIC_PREFIX):].decode("utf-8"))
    if payload.get("role") != "client":
        raise ValueError("invalid client role")
    return payload


def negotiate_socks5_client(sock):
    header = recv_exact(sock, 2)
    if header[0] != SOCKS_VERSION:
        sock.sendall(bytes([SOCKS_VERSION, SOCKS_METHOD_REJECT]))
        raise ValueError("unsupported SOCKS version")
    methods = recv_exact(sock, header[1])
    if SOCKS_METHOD_NOAUTH not in methods:
        sock.sendall(bytes([SOCKS_VERSION, SOCKS_METHOD_REJECT]))
        raise ValueError("no supported auth methods")
    sock.sendall(bytes([SOCKS_VERSION, SOCKS_METHOD_NOAUTH]))


def parse_socks5_connect_request(sock):
    header = recv_exact(sock, 4)
    if header[0] != SOCKS_VERSION:
        raise ValueError("unsupported SOCKS version")
    if header[1] != SOCKS_CMD_CONNECT:
        raise ValueError("unsupported SOCKS command")

    atyp = header[3]
    if atyp == SOCKS_ATYP_IPV4:
        host = socket.inet_ntoa(recv_exact(sock, 4))
    elif atyp == SOCKS_ATYP_DOMAIN:
        host = recv_exact(sock, recv_exact(sock, 1)[0]).decode("idna")
    elif atyp == SOCKS_ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise TypeError("unsupported SOCKS address type")

    port = int.from_bytes(recv_exact(sock, 2), "big")
    return host, port


def send_socks5_reply(sock, reply_code):
    sock.sendall(
        bytes(
            [
                SOCKS_VERSION,
                reply_code,
                0x00,
                SOCKS_ATYP_IPV4,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        )
    )


@dataclass
class OperatorStream:
    stream_id: int
    conn: socket.socket
    open_event: threading.Event = field(default_factory=threading.Event)
    open_success: bool = False
    open_error: str = ""


class ReverseProxyClientSession:
    def __init__(self, sock, frame_handler, close_handler, logger=None):
        self.sock = sock
        self.fileobj = sock.makefile("rb")
        self.frame_handler = frame_handler
        self.close_handler = close_handler
        self.logger = logger or (lambda _message: None)
        self.send_lock = threading.Lock()
        self.closed = False

    def start(self):
        thread = threading.Thread(target=self._reader_loop, daemon=True)
        thread.start()
        return thread

    def send(self, payload):
        send_frame(self.sock, payload, self.send_lock)

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.sock.close()
        finally:
            self.close_handler(self)

    def _reader_loop(self):
        try:
            while True:
                self.frame_handler(read_frame(self.fileobj))
        except Exception as exc:
            self.logger("reverse client disconnected: {}".format(exc))
        finally:
            self.close()


class ReverseSocksServer:
    def __init__(self, bind_host="127.0.0.1", bind_port=8080, client_host="127.0.0.1", client_port=8081, logger=None):
        self.bind_host = bind_host
        self.bind_port = int(bind_port)
        self.client_host = client_host
        self.client_port = int(client_port)
        self.logger = logger or (lambda _message: None)

        self.bind_listener = self._make_listener(self.bind_host, self.bind_port)
        self.client_listener = self._make_listener(self.client_host, self.client_port)

        self.client_lock = threading.Lock()
        self.client = None
        self.stream_lock = threading.Lock()
        self.streams = {}
        self.stream_counter = 1
        self.running = True

    @staticmethod
    def _make_listener(host, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, int(port)))
        listener.listen(50)
        return listener

    @property
    def bind_address(self):
        return self.bind_listener.getsockname()

    @property
    def client_address(self):
        return self.client_listener.getsockname()

    def serve_forever(self):
        acceptors = [
            threading.Thread(target=self._accept_clients, daemon=True),
            threading.Thread(target=self._accept_operators, daemon=True),
        ]
        for thread in acceptors:
            thread.start()
        try:
            for thread in acceptors:
                thread.join()
        finally:
            self.shutdown()

    def shutdown(self):
        if not self.running:
            return
        self.running = False
        for listener in (self.bind_listener, self.client_listener):
            try:
                listener.close()
            except OSError:
                pass
        with self.client_lock:
            client = self.client
            self.client = None
        if client is not None:
            try:
                client.sock.close()
            except OSError:
                pass
        with self.stream_lock:
            streams = list(self.streams.values())
            self.streams.clear()
        for stream in streams:
            try:
                stream.conn.close()
            except OSError:
                pass

    def _accept_clients(self):
        while self.running:
            try:
                conn, addr = self.client_listener.accept()
            except OSError:
                break
            threading.Thread(target=self._register_client, args=(conn, addr), daemon=True).start()

    def _accept_operators(self):
        while self.running:
            try:
                conn, addr = self.bind_listener.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_operator_connection, args=(conn, addr), daemon=True).start()

    def _register_client(self, conn, addr):
        fileobj = conn.makefile("rb")
        try:
            parse_client_hello(fileobj.readline())
        except Exception as exc:
            self.logger("invalid reverse client from {}:{}: {}".format(addr[0], addr[1], exc))
            conn.close()
            return

        client = ReverseProxyClientSession(conn, self._handle_client_frame, self._drop_client, self.logger)
        with self.client_lock:
            previous = self.client
            self.client = client
        if previous is not None:
            previous.close()
        self.logger("reverse client connected from {}:{}".format(addr[0], addr[1]))
        client.start()

    def _handle_operator_connection(self, conn, addr):
        if self._get_client() is None:
            conn.close()
            return

        try:
            negotiate_socks5_client(conn)
            target_host, target_port = parse_socks5_connect_request(conn)
        except ValueError as exc:
            if "command" in str(exc):
                send_socks5_reply(conn, SOCKS_REPLY_COMMAND_UNSUPPORTED)
            else:
                send_socks5_reply(conn, SOCKS_REPLY_GENERAL_FAILURE)
            conn.close()
            return
        except TypeError:
            send_socks5_reply(conn, SOCKS_REPLY_ADDRESS_UNSUPPORTED)
            conn.close()
            return
        except Exception:
            conn.close()
            return

        stream = self._create_stream(conn)
        self.logger("operator stream {} from {}:{} -> {}:{}".format(stream.stream_id, addr[0], addr[1], target_host, target_port))
        client = self._get_client()
        if client is None:
            self._close_stream(stream.stream_id)
            return

        try:
            client.send(
                {
                    "type": "open",
                    "stream_id": stream.stream_id,
                    "target_host": target_host,
                    "target_port": target_port,
                }
            )
        except Exception:
            self._close_stream(stream.stream_id)
            return

        stream.open_event.wait(timeout=10)
        if not stream.open_success:
            send_socks5_reply(conn, SOCKS_REPLY_GENERAL_FAILURE)
            self._close_stream(stream.stream_id)
            return

        send_socks5_reply(conn, SOCKS_REPLY_SUCCESS)
        self._operator_reader(stream.stream_id)

    def _operator_reader(self, stream_id):
        stream = self._get_stream(stream_id)
        if stream is None:
            return
        try:
            while True:
                data = stream.conn.recv(4096)
                if not data:
                    break
                client = self._get_client()
                if client is None:
                    break
                client.send({"type": "data", "stream_id": stream_id, "data": data.hex()})
        except OSError:
            pass
        finally:
            client = self._get_client()
            if client is not None:
                try:
                    client.send({"type": "close", "stream_id": stream_id})
                except OSError:
                    pass
            self._close_stream(stream_id)

    def _handle_client_frame(self, frame):
        frame_type = frame.get("type")
        stream_id = int(frame.get("stream_id", 0))
        stream = self._get_stream(stream_id)
        if stream is None:
            return

        if frame_type == "open_result":
            stream.open_success = bool(frame.get("ok"))
            stream.open_error = str(frame.get("error", ""))
            stream.open_event.set()
            return

        if frame_type == "data":
            payload = bytes.fromhex(frame.get("data", ""))
            if payload:
                try:
                    stream.conn.sendall(payload)
                except OSError:
                    self._close_stream(stream_id)
            return

        if frame_type in {"close", "error"}:
            self._close_stream(stream_id)

    def _drop_client(self, client):
        with self.client_lock:
            if self.client is client:
                self.client = None
        with self.stream_lock:
            stream_ids = list(self.streams.keys())
        for stream_id in stream_ids:
            self._close_stream(stream_id)

    def _create_stream(self, conn):
        with self.stream_lock:
            stream = OperatorStream(stream_id=self.stream_counter, conn=conn)
            self.streams[stream.stream_id] = stream
            self.stream_counter += 1
            return stream

    def _get_client(self):
        with self.client_lock:
            return self.client

    def _get_stream(self, stream_id):
        with self.stream_lock:
            return self.streams.get(stream_id)

    def _close_stream(self, stream_id):
        with self.stream_lock:
            stream = self.streams.pop(stream_id, None)
        if stream is None:
            return
        try:
            stream.conn.close()
        except OSError:
            pass

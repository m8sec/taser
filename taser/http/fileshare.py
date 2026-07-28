"""Simple local HTTP upload and download server helpers."""

from __future__ import annotations

import html
import os
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import quote, unquote

try:
    import cgi
except ImportError:  # pragma: no cover
    cgi = None


HTML_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Taser File Share</title>
</head>
<body>
  <h2>Upload File</h2>
  <form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
  </form>
  <hr>
  <h2>Files</h2>
  <ul>
    {items}
  </ul>
</body>
</html>
"""


@dataclass
class FileShareConfig:
    base_dir: Path
    host: str = "0.0.0.0"
    port: int = 8080
    allow_upload: bool = True


def _safe_resolve(base_dir: Path, relative_name: str) -> Path:
    candidate = (base_dir / relative_name).resolve()
    try:
        candidate.relative_to(base_dir.resolve())
    except ValueError as exc:
        raise PermissionError("Path escapes base directory") from exc
    return candidate


def render_listing(base_dir: Path) -> str:
    items = []
    for path in sorted(base_dir.iterdir(), key=lambda item: item.name.lower()):
        if not path.is_file():
            continue
        label = html.escape(path.name)
        href = quote(path.name)
        items.append(f'<li><a href="/files/{href}">{label}</a></li>')
    return HTML_TEMPLATE.format(items="\n    ".join(items))


def create_handler(config: FileShareConfig, logger: Callable[[str], None]):
    class FileShareHandler(BaseHTTPRequestHandler):
        server_version = "TaserFileShare/1.0"

        def _send_html(self, body: str, status: int = HTTPStatus.OK):
            payload = body.encode("utf-8", errors="replace")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _send_text(self, body: str, status: int):
            payload = body.encode("utf-8", errors="replace")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _send_file(self, file_path: Path):
            payload = file_path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Content-Disposition", f'attachment; filename="{file_path.name}"')
            self.end_headers()
            self.wfile.write(payload)

        def _log(self, message: str):
            logger(message)

        def log_message(self, format, *args):  # noqa: A003
            self._log("%s - %s" % (self.address_string(), format % args))

        def do_GET(self):  # noqa: N802
            if self.path == "/":
                self._send_html(render_listing(config.base_dir))
                return

            if not self.path.startswith("/files/"):
                self._send_text("Not found\n", HTTPStatus.NOT_FOUND)
                return

            try:
                requested_name = unquote(self.path[len("/files/"):])
                file_path = _safe_resolve(config.base_dir, requested_name)
            except PermissionError:
                self._send_text("Forbidden\n", HTTPStatus.FORBIDDEN)
                return

            if not file_path.exists() or not file_path.is_file():
                self._send_text("Not found\n", HTTPStatus.NOT_FOUND)
                return

            self._send_file(file_path)

        def do_POST(self):  # noqa: N802
            if self.path != "/":
                self._send_text("Not found\n", HTTPStatus.NOT_FOUND)
                return

            if not config.allow_upload:
                self._send_text("Uploads disabled\n", HTTPStatus.FORBIDDEN)
                return

            if cgi is None:
                self._send_text("Upload parser unavailable\n", HTTPStatus.INTERNAL_SERVER_ERROR)
                return

            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in content_type:
                self._send_text("Expected multipart/form-data\n", HTTPStatus.BAD_REQUEST)
                return

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": content_type,
                },
            )
            upload = form["file"] if "file" in form else None
            if upload is None or not getattr(upload, "filename", ""):
                self._send_text("Missing file field\n", HTTPStatus.BAD_REQUEST)
                return

            filename = os.path.basename(upload.filename)
            if not filename:
                self._send_text("Invalid filename\n", HTTPStatus.BAD_REQUEST)
                return

            destination = _safe_resolve(config.base_dir, filename)
            with open(destination, "wb") as handle:
                handle.write(upload.file.read())

            self._log(f"uploaded {destination}")
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/")
            self.end_headers()

    return FileShareHandler


class LocalFileShareServer:
    def __init__(self, base_dir, host="0.0.0.0", port=8080, allow_upload=True, logger=None):
        self.config = FileShareConfig(
            base_dir=Path(base_dir).expanduser().resolve(),
            host=host,
            port=port,
            allow_upload=allow_upload,
        )
        self.logger = logger or (lambda _message: None)
        self._server = ThreadingHTTPServer(
            (self.config.host, self.config.port),
            create_handler(self.config, self.logger),
        )

    def serve_forever(self):
        self._server.serve_forever()

    def shutdown(self):
        self._server.shutdown()

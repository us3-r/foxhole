#!/usr/bin/env python3
"""Small HTTP file server for transferring files between a host and a VM."""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import mimetypes
import os
import tempfile
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


CHUNK_SIZE = 1024 * 1024
DEFAULT_MAX_UPLOAD = 256 * 1024 * 1024


@dataclass(frozen=True)
class ServerConfig:
    files_dir: Path
    token: str | None
    max_upload: int


class FileServer(ThreadingHTTPServer):
    config: ServerConfig


class FileRequestHandler(BaseHTTPRequestHandler):
    server: FileServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: object) -> None:
        """Avoid making request handling depend on an attached stderr console."""
        del args

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        expected = self.server.config.token
        if expected is None:
            return True

        authorization = self.headers.get("Authorization", "")
        supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
        if not supplied:
            supplied = self.headers.get("X-Server-Token", "")

        if hmac.compare_digest(supplied, expected):
            return True

        self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
        return False

    def _request_path(self) -> str:
        return unquote(urlsplit(self.path).path)

    def _resolve_file(self, relative_name: str) -> Path | None:
        if not relative_name or "\x00" in relative_name:
            return None

        root = self.server.config.files_dir
        candidate = (root / relative_name).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return None
        return candidate

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if not self._authorized():
            return

        request_path = self._request_path()
        if request_path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return

        if request_path in ("/files", "/files/"):
            self._list_files()
            return

        if not request_path.startswith("/files/"):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        target = self._resolve_file(request_path[len("/files/") :])
        if target is None:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid file path"})
            return
        if not target.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "file not found"})
            return

        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        file_size = target.stat().st_size
        download_name = target.name.replace('"', "")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(file_size))
        self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        try:
            with target.open("rb") as source:
                while chunk := source.read(CHUNK_SIZE):
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _list_files(self) -> None:
        root = self.server.config.files_dir
        files = []
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                files.append(
                    {
                        "name": path.relative_to(root).as_posix(),
                        "size": path.stat().st_size,
                    }
                )
        self._send_json(HTTPStatus.OK, {"files": files})

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if not self._authorized():
            return

        request_path = self._request_path()
        if not request_path.startswith("/files/"):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        target = self._resolve_file(request_path[len("/files/") :])
        if target is None:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid file path"})
            return

        raw_length = self.headers.get("Content-Length")
        try:
            content_length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            content_length = -1

        if content_length < 0:
            self._send_json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length required"})
            return
        if content_length > self.server.config.max_upload:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "upload exceeds configured size limit"},
            )
            return

        target.parent.mkdir(parents=True, exist_ok=True)
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=target.parent, prefix=".upload-", delete=False
            ) as temporary:
                temporary_name = temporary.name
                remaining = content_length
                while remaining:
                    chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ConnectionError("client disconnected before upload completed")
                    temporary.write(chunk)
                    remaining -= len(chunk)
                temporary.flush()
                os.fsync(temporary.fileno())

            existed = target.exists()
            os.replace(temporary_name, target)
            temporary_name = None
        except (ConnectionError, OSError) as error:
            if temporary_name is not None:
                try:
                    Path(temporary_name).unlink(missing_ok=True)
                except OSError:
                    pass
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "upload failed", "detail": str(error)},
            )
            return

        self._send_json(
            HTTPStatus.OK if existed else HTTPStatus.CREATED,
            {
                "stored": target.relative_to(self.server.config.files_dir).as_posix(),
                "size": content_length,
            },
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Serve files to a VM and accept files uploaded by it."
    )
    parser.add_argument(
        "--host",
        default="192.168.250.1",
        help="dedicated Internal-switch host address (default: 192.168.250.1)",
    )
    parser.add_argument("--port", type=int, default=8080, help="TCP port (default: 8080)")
    parser.add_argument(
        "--files-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "files",
        help="directory exposed through /files",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("FOXHOLE_SERVER_TOKEN"),
        help="optional bearer token (or set FOXHOLE_SERVER_TOKEN)",
    )
    parser.add_argument(
        "--max-upload-mb",
        type=int,
        default=DEFAULT_MAX_UPLOAD // (1024 * 1024),
        help="maximum POST body size in MiB (default: 256)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        bind_address = ipaddress.IPv4Address(args.host)
    except ipaddress.AddressValueError as error:
        raise SystemExit(f"--host must be a literal IPv4 address: {error}") from error
    if bind_address.is_unspecified or bind_address.is_loopback or bind_address.is_link_local:
        raise SystemExit(
            "--host must be the fixed address of the dedicated Internal switch; "
            "wildcard, loopback, and link-local binds are refused"
        )
    if not 1 <= args.port <= 65535:
        raise SystemExit("--port must be between 1 and 65535")
    if args.max_upload_mb < 1:
        raise SystemExit("--max-upload-mb must be at least 1")

    files_dir = args.files_dir.resolve()
    files_dir.mkdir(parents=True, exist_ok=True)

    server = FileServer((args.host, args.port), FileRequestHandler)
    server.config = ServerConfig(
        files_dir=files_dir,
        token=args.token,
        max_upload=args.max_upload_mb * 1024 * 1024,
    )

    print(f"Serving {files_dir} on http://{args.host}:{args.port}")
    if args.token is None:
        print("Warning: no access token configured")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

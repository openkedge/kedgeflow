#!/usr/bin/env python3
"""Receive one digest-pinned public bundle through an operator SSM loopback tunnel.

Run only as a transient nonroot sandbox. No extraction, execution, credential,
policy change or public/VPC listener. The root launcher separately verifies the
bundle and stops the sandbox before any release activation.
"""

import argparse
import hashlib
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def handler(output, expected_size, expected_sha256):
    class Receiver(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def reply(self, status, value):
            raw = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)
            self.close_connection = True

        def do_PUT(self):
            if (
                self.client_address[0] != "127.0.0.1"
                or self.path != "/bundle"
                or self.headers.get_all("Content-Length") != [str(expected_size)]
                or self.headers.get("Content-Type") != "application/octet-stream"
                or self.headers.get("Transfer-Encoding") is not None
                or self.headers.get("Content-Encoding") is not None
            ):
                self.reply(400, {"status": "closed_upload_contract_required"})
                return
            partial = output.with_suffix(".incomplete")
            if output.exists() or partial.exists() or output.is_symlink() or partial.is_symlink():
                self.reply(409, {"status": "existing_upload_preserved"})
                return
            opened = False
            try:
                self.connection.settimeout(10)
                deadline = time.monotonic() + 180
                fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
                opened = True
                digest = hashlib.sha256()
                with os.fdopen(fd, "wb") as stream:
                    remaining = expected_size
                    while remaining:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("bounded upload deadline")
                        raw = self.rfile.read(min(65536, remaining))
                        if not raw:
                            raise ValueError("incomplete upload")
                        stream.write(raw)
                        digest.update(raw)
                        remaining -= len(raw)
                    if digest.hexdigest() != expected_sha256:
                        raise ValueError("upload digest mismatch")
                    stream.flush()
                    os.fsync(stream.fileno())
                partial.rename(output)
                directory_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                self.reply(
                    201,
                    {
                        "status": "digest_pinned_bundle_received",
                        "sha256": expected_sha256,
                        "bytes": expected_size,
                    },
                )
            except (OSError, ValueError, TimeoutError):
                if opened:
                    partial.unlink(missing_ok=True)
                self.reply(422, {"status": "upload_refused"})

        def do_GET(self):
            self.reply(405, {"status": "upload_only"})

        do_POST = do_GET
        do_DELETE = do_GET

    return Receiver


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--size", type=int, required=True)
    args = parser.parse_args()
    output = Path("/run/kf-cura-release-upload/bundle.tar.gz")
    root = output.parent
    info = root.lstat()
    if (
        os.geteuid() == 0
        or root.is_symlink()
        or not root.is_dir()
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o7777 != 0o700
        or any(root.iterdir())
        or not re.fullmatch(r"[a-f0-9]{64}", args.sha256)
        or not 1 <= args.size <= 256 << 20
    ):
        raise RuntimeError("transient private upload custody required")
    server = HTTPServer(("127.0.0.1", 18765), handler(output, args.size, args.sha256))
    server.timeout = 5
    deadline = time.monotonic() + 600
    try:
        while time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError):
        print('{"status":"failed","phase":"transient_upload_preconditions"}')
        raise SystemExit(1) from None

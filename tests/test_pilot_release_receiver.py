"""The SSM-only upload endpoint accepts exactly the pinned public bytes once."""

import hashlib
import http.client
import runpy
import threading
from contextlib import contextmanager
from http.server import HTTPServer
from pathlib import Path

MODULE = runpy.run_path(str(Path(__file__).parents[1] / "scripts/pilot-release-receiver.py"))


@contextmanager
def receiver(tmp_path, expected=b"public release"):
    path = tmp_path / "bundle.tar.gz"
    server = HTTPServer(
        ("127.0.0.1", 0),
        MODULE["handler"](path, len(expected), hashlib.sha256(expected).hexdigest()),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield path, server.server_address[1], expected
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def send(port, body, path="/bundle", headers=None, method="PUT"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            method, path, body, headers or {"Content-Type": "application/octet-stream"}
        )
        response = connection.getresponse()
        result = response.status, response.read()
        return result
    finally:
        connection.close()


def test_exact_upload_is_flushed_and_cannot_be_overwritten(tmp_path):
    with receiver(tmp_path) as (path, port, expected):
        assert send(port, expected)[0] == 201
        assert path.read_bytes() == expected
        assert path.stat().st_mode & 0o777 == 0o400
        assert send(port, expected)[0] == 409
        assert path.read_bytes() == expected


def test_wrong_digest_never_becomes_a_release_and_valid_retry_can_succeed(tmp_path):
    with receiver(tmp_path) as (path, port, expected):
        assert send(port, b"x" * len(expected))[0] == 422
        assert not path.exists() and not path.with_suffix(".incomplete").exists()
        assert send(port, expected)[0] == 201


def test_endpoint_refuses_arbitrary_paths_sizes_methods_and_content_codings(tmp_path):
    with receiver(tmp_path) as (path, port, expected):
        assert send(port, expected, path="/other")[0] == 400
        assert send(port, expected[:-1])[0] == 400
        assert send(port, expected, method="GET")[0] == 405
        assert (
            send(
                port,
                expected,
                headers={"Content-Type": "application/octet-stream", "Content-Encoding": "gzip"},
            )[0]
            == 400
        )
        assert not path.exists()

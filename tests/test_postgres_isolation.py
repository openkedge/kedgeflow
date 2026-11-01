"""Disposable fixture guards, real TLS probes and failed-run process cleanup."""

import json
import os
import runpy
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/qualify-postgres-isolation.py"))


def test_account_fixture_refuses_without_disposable_host_opt_in():
    # Missing binaries cannot be inspected and no account tool can be called.
    with pytest.raises(RuntimeError, match="requires --ephemeral-host"):
        SCRIPT["qualify"](Path("/nonexistent"), Path("/nonexistent"), False)


def test_target_process_is_reaped_when_a_probe_fails():
    with pytest.raises(RuntimeError, match="probe failure"):
        with SCRIPT["target_process"](
            [sys.executable, "-c", "import time; time.sleep(60)"], dict(os.environ),
        ) as child:
            assert child.poll() is None
            raise RuntimeError("probe failure")
    assert child.poll() is not None
    with pytest.raises(ProcessLookupError):
        os.killpg(child.pid, 0)


def test_https_probe_preserves_http_refusal_and_distinguishes_missing_mtls(tmp_path):
    def run(args):
        return subprocess.run(args, check=True, capture_output=True, text=True)

    run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
         "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=fixture-ca",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-keyout", str(tmp_path / "ca.key"), "-out", str(tmp_path / "ca.pem")])
    server_cert, server_key = SCRIPT["issue_certificate"](
        run, tmp_path, "server", "IP:127.0.0.1", "serverAuth",
    )
    cert, key = SCRIPT["issue_certificate"](
        run, tmp_path, "recovery", "URI:spiffe://example.org/recovery", "clientAuth",
    )
    secret = "private-test-bearer-do-not-report"

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.headers["Content-Type"] == "application/json"
            assert json.loads(self.rfile.read(int(self.headers["Content-Length"]))) == {
                "operation": "query",
            }
            valid = self.headers["Authorization"] == "Bearer " + secret
            self.send_response(404 if valid else 401)
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "unknown_outcome" if valid else "invalid_credential",
            }).encode())

        def log_message(self, *_args):
            pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(server_cert, server_key)
    context.load_verify_locations(tmp_path / "ca.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    class Server(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(2)
            try:
                return context.wrap_socket(connection, server_side=True), address
            except BaseException:
                connection.close()
                raise

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        packet = {
            "ca": str(tmp_path / "ca.pem"), "certificate": str(cert), "key": str(key),
            "url": f"https://127.0.0.1:{server.server_port}/query", "token": secret,
            "body": {"operation": "query"},
        }

        def probe():
            result = subprocess.run(
                [sys.executable, "-c", SCRIPT["HTTPS_PROBE"]], input=json.dumps(packet),
                capture_output=True, text=True, check=True, timeout=5,
            )
            assert secret not in result.stdout + result.stderr
            return json.loads(result.stdout)

        assert probe() == {"status": 404, "body": {"error": "unknown_outcome"}}
        packet["token"] = "wrong"
        assert probe() == {"status": 401, "body": {"error": "invalid_credential"}}
        del packet["certificate"]
        # A TLS 1.3 certificate alert may close the connection while urllib is
        # writing, surfacing as a pipe/reset error instead of an SSL exception.
        assert probe() in [
            {"transport_error": name}
            for name in ("SSLError", "BrokenPipeError", "ConnectionResetError")
        ]
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

"""Test-only loopback Kubernetes gate for a single owned Terraform mutation.

It forwards a fixed upstream using its pinned CA. No caller-selected routing,
production API, ambient credential acquisition or mutation retry is provided.
"""

import hashlib
import http.server
import json
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


class ActiveGate:
    def __init__(self, private, connection, namespace, target):
        self.root = private / "active-gate"
        self.root.mkdir(mode=0o700)
        self.path = f"/api/v1/namespaces/{namespace}/configmaps/{target}"
        self.upstream = connection["server"]
        if urlparse(self.upstream).hostname != "127.0.0.1":
            raise ValueError("active gate requires the explicit owned loopback API")
        import base64

        ca = self.root / "upstream.pem"
        ca.write_bytes(base64.b64decode(connection["certificate-authority-data"]))
        self.context = ssl.create_default_context(cafile=str(ca))
        root_cert = self.root / "root.pem"
        root_key = self.root / "root.key"
        cert = self.root / "gate.pem"
        key = self.root / "gate.key"
        config = self.root / "openssl.cnf"
        config.write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n"
            "[dn]\nCN=127.0.0.1\n[ext]\nsubjectAltName=IP:127.0.0.1\n"
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n"
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-config",
                str(config),
                "-keyout",
                str(root_key),
                "-out",
                str(root_cert),
            ],
            check=True,
            capture_output=True,
            timeout=20,
        )
        config.write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=ext\n"
            "[dn]\nCN=127.0.0.1\n[ext]\nsubjectAltName=IP:127.0.0.1\n"
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
        )
        csr = self.root / "gate.csr"
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-config",
                str(config),
                "-keyout",
                str(key),
                "-out",
                str(csr),
            ],
            check=True,
            capture_output=True,
            timeout=20,
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(root_cert),
                "-CAkey",
                str(root_key),
                "-CAcreateserial",
                "-days",
                "1",
                "-extfile",
                str(config),
                "-extensions",
                "ext",
                "-out",
                str(cert),
            ],
            check=True,
            capture_output=True,
            timeout=20,
        )
        for p in self.root.iterdir():
            p.chmod(0o600)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.entries = []
        self.requests = []
        gate = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def handle_request(self):
                with gate.lock:
                    trace = {
                        "method": self.command,
                        "path": urlparse(self.path).path,
                        "transfer_encoding": self.headers.get("Transfer-Encoding"),
                        "content_length": self.headers.get("Content-Length"),
                        "status": None,
                    }
                    gate.requests.append(trace)
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > 1 << 20 or self.headers.get("Transfer-Encoding"):
                    trace["status"] = 400
                    self.send_error(400)
                    return
                body = self.rfile.read(length) if length else None
                mutation = self.command != "GET"
                entry = None
                if mutation:
                    if self.command not in ("PATCH", "PUT") or self.path != gate.path:
                        trace["status"] = 403
                        self.send_error(403)
                        return
                    with gate.lock:
                        if gate.entries or not (gate.root / "armed").exists():
                            trace["status"] = 409
                            self.send_error(409)
                            return
                        entry = {
                            "method": self.command,
                            "path": self.path,
                            "body_sha256": hashlib.sha256(body or b"").hexdigest(),
                            "received_at_ms": time.time_ns() // 1_000_000,
                            "forwarded": False,
                            "upstream_status": None,
                        }
                        gate.entries.append(entry)
                        gate.record("entered.json", entry)
                    until = time.monotonic() + 90
                    while not gate.stop.is_set() and time.monotonic() < until:
                        if (gate.root / "release.json").exists():
                            break
                        gate.stop.wait(0.02)
                    action = "drop"
                    if not gate.stop.is_set() and (gate.root / "release.json").exists():
                        action = json.loads((gate.root / "release.json").read_text())["action"]
                    entry["released_at_ms"] = time.time_ns() // 1_000_000
                    if action != "forward":
                        gate.record("completed.json", entry)
                        try:
                            self.send_error(503)
                        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                            pass
                        return
                    entry["forwarded"] = True
                    entry["forwarded_at_ms"] = time.time_ns() // 1_000_000
                headers = {
                    k: v
                    for k, v in self.headers.items()
                    if k.lower() not in ("host", "connection", "content-length", "accept-encoding")
                }
                req = urllib.request.Request(
                    gate.upstream + self.path, data=body, headers=headers, method=self.command
                )
                try:
                    opener = urllib.request.build_opener(
                        urllib.request.ProxyHandler({}),
                        urllib.request.HTTPSHandler(context=gate.context),
                    )
                    answer = opener.open(req, timeout=12)
                except urllib.error.HTTPError as error:
                    answer = error
                except Exception as error:
                    trace["error_class"] = type(error).__name__
                    if entry:
                        entry["upstream_error"] = True
                        gate.record("completed.json", entry)
                    self.close_connection = True
                    return
                with answer:
                    data = answer.read(2 << 20)
                    status = answer.status
                    trace["status"] = status
                    if entry:
                        entry["upstream_status"] = status
                        entry["completed_at_ms"] = time.time_ns() // 1_000_000
                        gate.record("completed.json", entry)
                    try:
                        self.send_response(status)
                        self.send_header(
                            "Content-Type", answer.headers.get("Content-Type", "application/json")
                        )
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                    except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                        pass

            do_GET = handle_request
            do_PATCH = handle_request
            do_PUT = handle_request
            do_POST = handle_request
            do_DELETE = handle_request

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(str(cert), str(key))
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.connection = {
            "server": f"https://127.0.0.1:{self.server.server_port}",
            "certificate-authority-data": base64.b64encode(root_cert.read_bytes()).decode(),
        }

    def record(self, name, value):
        temporary = self.root / (name + ".tmp")
        temporary.write_text(json.dumps(value))
        temporary.chmod(0o600)
        temporary.replace(self.root / name)

    def close(self):
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

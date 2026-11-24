#!/usr/bin/env python3
"""Probe the shipping agent sandbox on an unenrolled Linux host, without credentials.

Uses a transient service and a disposable loopback TCP listener. Never contacts
an application action, requests metadata tokens, reads secrets or enrolls an agent.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import uuid
from pathlib import Path


def probe(allowed_peer=None):
    if os.geteuid() != 0:
        raise RuntimeError("root required for transient systemd sandbox inspection")
    if allowed_peer and ipaddress.ip_address(allowed_peer) not in ipaddress.ip_network(
        "10.87.0.0/16"
    ):
        raise RuntimeError("positive control must be the exact private Services host")
    unit = Path("/opt/kedgeflow/pilot-source/deploy/pilot/cura/kedgeflow-agent.service")
    raw = unit.read_text()
    properties, section = [], None
    omitted = {"Type", "WorkingDirectory", "ExecStart", "StandardOutput", "StandardError"}
    for line in raw.splitlines():
        if line.startswith("["):
            section = line
        elif section == "[Service]" and line and not line.startswith("#"):
            name, _, value = line.partition("=")
            if name not in omitted:
                properties.append(f"--property={name}={value}")
    if "--property=IPAddressDeny=any" not in properties:
        raise RuntimeError("shipping agent network boundary absent")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        connect = (
            "import socket; s=socket.create_connection(('127.0.0.1',"
            + str(port)
            + "),timeout=2); s.close()"
        )
        subprocess.run(
            ["runuser", "-u", "kf-agent", "--", "/usr/bin/python3", "-I", "-c", connect],
            check=True,
            capture_output=True,
            timeout=10,
        )
        child = f"""
import json,socket,subprocess,sys
def blocked(host,port):
 try:
  socket.create_connection((host,port),timeout=2).close()
  return False
 except OSError:
  return True
result={{'loopback_denied':blocked('127.0.0.1',{port}),
 'metadata_tcp_denied':blocked('169.254.169.254',80),
 'public_tcp_denied':blocked('1.1.1.1',443)}}
child=subprocess.run([sys.executable,'-I','-c',{connect!r}],capture_output=True,timeout=5)
result['descendant_loopback_denied']=child.returncode!=0
if {allowed_peer!r}:
 result['private_services_tcp_allowed']=not blocked({allowed_peer!r},8443)
print(json.dumps(result))
sys.exit(0 if all(result.values()) else 1)
"""
        result = subprocess.run(
            [
                "systemd-run",
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--unit=kedgeflow-agent-boundary-" + uuid.uuid4().hex[:12],
                *properties,
                "/usr/bin/python3",
                "-I",
                "-c",
                child,
            ],
            capture_output=True,
            text=True,
            timeout=40,
        )
        if result.returncode:
            raise RuntimeError("shipping agent sandbox did not enforce the bounded TCP probes")
        observations = json.loads(result.stdout)
    return {
        "format": "kedgeflow-cura-agent-boundary-v1",
        "scope": "transient shipping sandbox; loopback control and TCP negatives only",
        "status": "passed_bounded_network_checks",
        "unconfined_same_uid_loopback_control": True,
        "shipping_unit_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "observations": observations,
        "metadata_credentials_requested": False,
        "application_action_exercised": False,
        "private_services_control_requested": allowed_peer is not None,
        "production_qualified": False,
        "execution_authority": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allowed-peer", help="exact Services private IP with disposable TCP listener"
    )
    args = parser.parse_args()
    print(json.dumps(probe(args.allowed_peer), indent=2))

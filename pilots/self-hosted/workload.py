"""Run as the registered UID; private tokens and keys never go to stdout."""

import base64
import json
import re
import secrets
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def compact(header, claims, key):
    raw = ".".join(b64(json.dumps(v, separators=(",", ":")).encode()) for v in (header, claims))
    return raw + "." + b64(key.sign(raw.encode()))


def main():
    private = Path("/run/pilot")
    config = json.loads((private / "client.json").read_text())
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64(public)}
    endpoint = "https://keycloak:8443/realms/kedgeflow-pilot/protocol/openid-connect/token"
    proof = compact(
        {"alg": "EdDSA", "typ": "dpop+jwt", "jwk": jwk},
        {
            "jti": secrets.token_hex(16),
            "htm": "POST",
            "htu": endpoint,
            "iat": int(time.time()),
        },
        key,
    )
    context = ssl.create_default_context(cafile=str(private / "keycloak-ca.pem"))
    data = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": "kf-pilot-agent",
            "client_secret": config["client_secret"],
            "scope": config.get("scopes", "resource:mutate kf.status"),
        }
    ).encode()
    request = urllib.request.Request(endpoint, data=data, headers={"DPoP": proof})
    with urllib.request.urlopen(request, context=context, timeout=10) as response:
        issued = json.load(response)
    if issued["token_type"].lower() != "dpop":
        raise RuntimeError("Keycloak did not issue a sender-constrained token")
    with urllib.request.urlopen(
        endpoint.removesuffix("token") + "certs", context=context, timeout=10
    ) as response:
        jwks = json.load(response)
    claims = json.loads(base64.urlsafe_b64decode(issued["access_token"].split(".")[1] + "=="))
    header = json.loads(base64.urlsafe_b64decode(issued["access_token"].split(".")[0] + "=="))
    (private / "subject-shape.json").write_text(
        json.dumps(
            {
                "header": header,
                "claims": sorted(claims),
                "type": claims.get("typ"),
                "confirmation_fields": sorted(claims.get("cnf", {})),
                "confirmation_type": claims.get("cnf", {}).get("kc-jkt-type"),
            }
        )
    )
    agent = "/opt/spire/bin/spire-agent"
    args = ["-socketPath", "/run/kf-spire/agent.sock", "-timeout", "10s"]
    deadline = time.monotonic() + 20
    while True:
        result = subprocess.run(
            [
                agent,
                "api",
                "fetch",
                "jwt",
                *args,
                "-audience",
                config.get("actor_audience", "https://broker.pilot.kedgeflow.test/token"),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("SPIRE workload fetch refused: " + result.stderr[-1000:])
        time.sleep(0.5)
    tokens = re.findall(
        r"\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{40,})\b", result.stdout
    )
    if len(tokens) != 1:
        raise RuntimeError("SPIRE returned an ambiguous JWT-SVID set")
    x509 = private / "x509"
    x509.mkdir(mode=0o700, exist_ok=True)
    subprocess.run(
        [agent, "api", "fetch", "x509", *args, "-silent", "-write", str(x509)],
        check=True,
        capture_output=True,
        timeout=15,
    )
    packet = {
        "subject_token": issued["access_token"],
        "actor_token": tokens[0],
        "keycloak_jwks": jwks,
        "dpop_seed": b64(
            key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ),
    }
    destination = private / "packet.json"
    destination.write_text(json.dumps(packet))
    destination.chmod(0o600)
    claims = json.loads(base64.urlsafe_b64decode(issued["access_token"].split(".")[1] + "=="))
    header = json.loads(base64.urlsafe_b64decode(issued["access_token"].split(".")[0] + "=="))
    print(
        json.dumps(
            {
                "status": "issued",
                "subject_header": header,
                "subject_claim_names": sorted(claims),
                "token_type": issued["token_type"],
                "x509_files": sorted(p.name for p in x509.iterdir()),
            }
        )
    )


if __name__ == "__main__":
    main()

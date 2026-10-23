#!/usr/bin/env python3
"""Check actual controller/observer permissions in an owned drain fixture.

Never prints credentials or response bodies. No administrator identity is used.
"""

import argparse
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path


def run(directory: Path) -> dict:
    c = json.loads((directory / "contract.json").read_text())
    f = json.loads((directory / "fixture-public.json").read_text())
    if not f["cluster"].startswith("kf8-") or not f["namespace"].startswith("kf-drain-"):
        raise ValueError("explicit task-owned fixture required")
    ns = f["namespace"]
    pod = f["original_pod"]["name"]
    target = c["node"]["name"]
    other = next(p["name"] for p in c["availability_nodes"] if p["name"] != target)
    ctx = ssl.create_default_context(cafile=str(directory / "ca.pem"))
    client = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx)
    )
    cases = [
        ("observer", "GET", "/api/v1/nodes/" + target, None, 200),
        ("mutator", "PATCH", "/api/v1/nodes/" + target + "?dryRun=All", [], 200),
        ("observer", "PATCH", "/api/v1/nodes/" + target, [], 403),
        ("mutator", "PATCH", "/api/v1/nodes/" + other, [], 403),
        ("mutator", "GET", f"/api/v1/namespaces/{ns}/secrets/forbidden", None, 403),
        ("mutator", "DELETE", f"/api/v1/namespaces/{ns}/pods/{pod}", {}, 403),
        (
            "observer",
            "POST",
            f"/api/v1/namespaces/{ns}/pods/{pod}/eviction",
            {
                "apiVersion": "policy/v1",
                "kind": "Eviction",
                "metadata": {"name": pod, "namespace": ns},
            },
            403,
        ),
    ]
    results = []
    for role, method, path, body, expected in cases:
        request = urllib.request.Request(
            c["api_origin"].rstrip("/") + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={
                "Authorization": "Bearer " + (directory / (role + ".token")).read_text().strip(),
                "Content-Type": (
                    "application/json-patch+json" if method == "PATCH" else "application/json"
                ),
            },
            method=method,
        )
        try:
            with client.open(request, timeout=10) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
        if status != expected:
            raise RuntimeError(
                f"RBAC mismatch: {role} {method} {path}: {status}, expected {expected}"
            )
        results.append({"role": role, "method": method, "path": path, "status": status})
    return {
        "status": "passed", "scope": "actual owned API service-account requests", "cases": results
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.fixture.resolve())
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": "passed", "cases": len(result["cases"])}))

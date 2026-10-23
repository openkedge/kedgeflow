#!/usr/bin/env python3
"""Bounded administrator setup/cleanup in an explicitly selected owned fixture.

This is test infrastructure, never an agent/controller credential or physical
inverse. Readiness gates model fixture availability only.
"""

import argparse
import json
import re
import subprocess
import time
from pathlib import Path


def run(args):
    f = json.loads((args.fixture / "fixture-public.json").read_text())
    c = json.loads((args.fixture / "contract.json").read_text())
    cluster, ns, target = f["cluster"], f["namespace"], c["node"]["name"]
    if (
        not re.fullmatch(r"kf8-[a-z0-9-]+", cluster)
        or args.context != "kind-" + cluster
        or not re.fullmatch(r"kf-drain-[a-f0-9]{16}", ns)
        or target != cluster + "-worker"
    ):
        raise ValueError("explicit owned fixture/context required")
    prefix = [str(args.kubectl.resolve()), "--kubeconfig", str(args.kubeconfig.resolve()),
              "--context", args.context, "--request-timeout=10s"]

    def kubectl(*cmd, body=None):
        r = subprocess.run(prefix + list(cmd), text=True, capture_output=True, check=False,
                           input=None if body is None else json.dumps(body))
        if r.returncode:
            raise RuntimeError("owned fixture administrator operation failed: " + cmd[0])
        return r.stdout

    def get(kind, name=None, namespace=None):
        cmd = ["get", kind]
        if name:
            cmd.append(name)
        if namespace:
            cmd += ["-n", namespace]
        return json.loads(kubectl(*cmd, "-o", "json"))

    realm = get("namespace", "kube-system")
    node = get("node", target)
    namespace = get("namespace", ns)
    if (
        realm["metadata"]["uid"] != c["cluster_uid"]
        or node["metadata"]["uid"] != c["node"]["uid"]
        or namespace["metadata"].get("labels", {}).get("kedgeflow.dev/fixture-owner") != cluster
    ):
        raise ValueError("owned cluster, node or namespace identity changed")
    if args.operation == "cleanup":
        operation = node["metadata"].get("annotations", {}).get("kedgeflow.dev/drain-operation")
        if operation is not None:
            if not re.fullmatch(r"[a-f0-9]{64}", operation):
                raise ValueError("unrecognized cordon owner")
            patch = [
                {"op": "test", "path": "/metadata/uid", "value": c["node"]["uid"]},
                {"op": "test", "path": "/metadata/resourceVersion",
                 "value": node["metadata"]["resourceVersion"]},
                {"op": "remove", "path": "/metadata/annotations/kedgeflow.dev~1drain-operation"},
                {"op": "add", "path": "/spec/unschedulable", "value": False},
            ]
            kubectl("patch", "node", target, "--type=json", "-p", json.dumps(patch))
        elif node["spec"].get("unschedulable"):
            raise ValueError("refuse cleanup of an unrelated cordon")
        for suffix in ["-read", "-patch"]:
            binding = get("clusterrolebinding", ns + suffix)
            if any(s.get("namespace") != ns for s in binding["subjects"]):
                raise ValueError("unexpected fixture role binding")
            kubectl("delete", "clusterrolebinding", ns + suffix)
            kubectl("delete", "clusterrole", ns + suffix)
        kubectl("delete", "namespace", ns, "--wait=true", "--timeout=60s")
    elif args.operation in ["touch-target-pod", "recreate-target-pod"]:
        pin = f["original_pod"]
        pod = get("pod", pin["name"], ns)
        if (
            pod["metadata"]["uid"] != pin["uid"]
            or pod["spec"].get("nodeName") != target
            or not any(o["uid"] == c["workload"]["replica_set"]["uid"]
                       for o in pod["metadata"].get("ownerReferences", []))
        ):
            raise ValueError("exact original owned pod required")
        if args.operation == "touch-target-pod":
            kubectl("patch", "pod", pin["name"], "-n", ns, "--type=json", "-p", json.dumps([
                {"op": "test", "path": "/metadata/uid", "value": pin["uid"]},
                {"op": "test", "path": "/metadata/resourceVersion",
                 "value": pod["metadata"]["resourceVersion"]},
                ({"op": "add", "path": "/metadata/annotations/kedgeflow.dev~1fixture-touch",
                  "value": "changed-after-original-request"} if "annotations" in pod["metadata"]
                 else {"op": "add", "path": "/metadata/annotations",
                       "value": {"kedgeflow.dev/fixture-touch": "changed-after-original-request"}}),
            ]))
        else:
            # Explicit administrator test fault, never a controller fallback.
            # The replacement has no workload selector/owner, so ReplicaSet
            # reconciliation cannot adopt or remove this exact test identity.
            kubectl("delete", "pod", pin["name"], "-n", ns, "--wait=true", "--timeout=30s")
            kubectl("create", "-f", "-", body={
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": pin["name"], "namespace": ns,
                             "labels": {"kedgeflow.dev/recreated-fixture": cluster}},
                "spec": pod["spec"],
            })
            replacement = get("pod", pin["name"], ns)
            if replacement["metadata"]["uid"] == pin["uid"]:
                raise RuntimeError("replacement UID did not change")
    else:
        pods = get("pods", namespace=ns)["items"]
        others = sorted(
            (p for p in pods if p["spec"].get("nodeName") not in [None, target]),
            key=lambda p: p["metadata"]["name"],
        )
        if len(others) != 2:
            raise ValueError("two remaining original fixture pods required")
        selected = others[:1] if args.operation == "block" else others
        for pod in selected:
            patch = {"status": {"conditions": [{"type": "kedgeflow.dev/fixture-ready",
                     "status": "False" if args.operation == "block" else "True"}]}}
            kubectl("patch", "pod", pod["metadata"]["name"], "-n", ns,
                    "--subresource=status", "--type=strategic", "-p", json.dumps(patch))
        until = time.monotonic() + 15
        while time.monotonic() < until:
            pdb = get("pdb", "orders-fixture", ns)
            deployment = get("deployment", "orders-fixture", ns)
            allowed = pdb["status"].get("disruptionsAllowed", 0)
            available = deployment["status"].get("availableReplicas", 0)
            if args.operation == "block" and allowed == 0 and available == 2:
                break
            if args.operation == "unblock" and allowed >= 1 and available == 3:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("owned fixture availability transition timed out")
    print(json.dumps({"status": "passed", "operation": args.operation, "namespace": ns}))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("operation", choices=["block", "unblock", "cleanup",
                                         "touch-target-pod", "recreate-target-pod"])
    for name in ["fixture", "kubectl", "kubeconfig"]:
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--context", required=True)
    run(p.parse_args())

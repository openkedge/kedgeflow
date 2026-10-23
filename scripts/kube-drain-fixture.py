#!/usr/bin/env python3
"""Create bounded drain fixtures only in an explicitly named task-owned kind cluster."""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path


def run(args):
    if not re.fullmatch(r"kf8-[a-z0-9-]+", args.cluster):
        raise ValueError("only an explicitly owned kf8 kind cluster is supported")
    if args.context != "kind-" + args.cluster or not re.fullmatch(
        r"kf-drain-[a-f0-9]{16}", args.namespace
    ):
        raise ValueError("owned cluster context/namespace mismatch")
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    prefix = [
        str(args.kubectl.resolve()),
        "--kubeconfig",
        str(args.kubeconfig.resolve()),
        "--context",
        args.context,
        "--request-timeout=10s",
    ]

    def kubectl(*cmd, value=None):
        r = subprocess.run(
            prefix + list(cmd),
            input=json.dumps(value) if value is not None else None,
            text=True,
            capture_output=True,
            check=False,
        )
        if r.returncode:
            raise RuntimeError("owned fixture kubectl command failed: " + cmd[0])
        return r.stdout

    def get(kind, name=None, ns=None):
        cmd = ["get", kind]
        if name:
            cmd.append(name)
        if ns:
            cmd += ["-n", ns]
        return json.loads(kubectl(*cmd, "-o", "json"))

    nodes = get("nodes")["items"]
    if len(nodes) != 3 or any(
        not n["metadata"]["name"].startswith(args.cluster + "-") for n in nodes
    ):
        raise ValueError("not the bounded owned three-node fixture")
    target = args.cluster + "-worker"
    if target not in [n["metadata"]["name"] for n in nodes]:
        raise ValueError("owned target node missing")
    for n in nodes:
        if n["spec"].get("unschedulable") or n["metadata"].get("annotations", {}).get(
            "kedgeflow.dev/drain-operation"
        ):
            raise ValueError("owned fixture node needs explicit cleanup before reuse")
    # Permit fixture workload scheduling on this owned control-plane node only.
    cp = args.cluster + "-control-plane"
    taints = [t for n in nodes if n["metadata"]["name"] == cp for t in n["spec"].get("taints", [])]
    if any(t["key"] == "node-role.kubernetes.io/control-plane" for t in taints):
        kubectl("taint", "node", cp, "node-role.kubernetes.io/control-plane:NoSchedule-")
    ns = args.namespace
    labels = {"app": "kf-drain-fixture", "kedgeflow.dev/fixture-owner": args.cluster}
    items = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": ns, "labels": {"kedgeflow.dev/fixture-owner": args.cluster}},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "orders-fixture", "namespace": ns},
            "spec": {
                "replicas": 3,
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "terminationGracePeriodSeconds": 1,
                        "readinessGates": [{"conditionType": "kedgeflow.dev/fixture-ready"}],
                        "affinity": {
                            "podAntiAffinity": {
                                "requiredDuringSchedulingIgnoredDuringExecution": [
                                    {
                                        "labelSelector": {"matchLabels": labels},
                                        "topologyKey": "kubernetes.io/hostname",
                                    }
                                ]
                            }
                        },
                        "containers": [
                            {
                                "name": "fixture",
                                "image": "registry.k8s.io/pause:3.10",
                                "imagePullPolicy": "Never",
                                "resources": {
                                    "requests": {"cpu": "1m", "memory": "8Mi"},
                                    "limits": {"cpu": "100m", "memory": "32Mi"},
                                },
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]},
                                    "runAsNonRoot": True,
                                    "runAsUser": 65534,
                                    "seccompProfile": {"type": "RuntimeDefault"},
                                },
                            }
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": {"name": "orders-fixture", "namespace": ns},
            "spec": {"minAvailable": 2, "selector": {"matchLabels": labels}},
        },
        *[
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": name, "namespace": ns},
                "automountServiceAccountToken": False,
            }
            for name in ["mutator", "observer"]
        ],
    ]
    kubectl("create", "-f", "-", value={"apiVersion": "v1", "kind": "List", "items": items})
    until = time.monotonic() + 120
    pods = []
    while time.monotonic() < until:
        pods = get("pods", ns=ns)["items"]
        if len(pods) == 3 and all(
            p["spec"].get("nodeName")
            and p["status"].get("containerStatuses")
            and all(c.get("ready") for c in p["status"]["containerStatuses"])
            for p in pods
        ):
            break
        time.sleep(0.3)
    else:
        raise RuntimeError("fixture containers did not become ready")
    for p in pods:
        kubectl(
            "patch",
            "pod",
            p["metadata"]["name"],
            "-n",
            ns,
            "--subresource=status",
            "--type=strategic",
            "-p",
            json.dumps(
                {
                    "status": {
                        "conditions": [{"type": "kedgeflow.dev/fixture-ready", "status": "True"}]
                    }
                }
            ),
        )
    while time.monotonic() < until:
        deployment = get("deployment", "orders-fixture", ns)
        if deployment["status"].get("availableReplicas") == 3:
            break
        time.sleep(0.3)
    else:
        raise RuntimeError("fixture deployment did not reach three available replicas")
    pods = get("pods", ns=ns)["items"]
    selected = [p for p in pods if p["spec"]["nodeName"] == target]
    if len(selected) != 1:
        raise ValueError("one target pod is required")
    owner = [o for o in selected[0]["metadata"]["ownerReferences"] if o.get("controller")][0]
    replica_set = get("replicaset", owner["name"], ns)
    pdb = get("pdb", "orders-fixture", ns)
    cluster = get("namespace", "kube-system")
    nodes = get("nodes")["items"]
    target_node = [n for n in nodes if n["metadata"]["name"] == target][0]
    node_pods = json.loads(
        kubectl("get", "pods", "-A", "--field-selector", "spec.nodeName=" + target, "-o", "json")
    )["items"]
    daemon_sets = []
    for p in node_pods:
        for o in p["metadata"].get("ownerReferences", []):
            if o.get("controller") and o["kind"] == "DaemonSet":
                daemon_sets.append(
                    {
                        "namespace": p["metadata"]["namespace"],
                        "object": {"name": o["name"], "uid": o["uid"]},
                    }
                )
    config = json.loads(kubectl("config", "view", "--minify", "--raw", "-o", "json"))
    server = config["clusters"][0]["cluster"]
    ca = base64.b64decode(server["certificate-authority-data"], validate=True)

    def save(name, value):
        with (out / name).open("xb") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(value)

    save("ca.pem", ca)
    contract = {
        "profile": "KF-KUBE-DRAIN-0.1-draft",
        "cluster_uid": cluster["metadata"]["uid"],
        "api_origin": server["server"].rstrip("/") + "/",
        "ca_sha256": hashlib.sha256(ca).hexdigest(),
        "node": {"name": target, "uid": target_node["metadata"]["uid"]},
        "generation": 1,
        "availability_nodes": [
            {"name": n["metadata"]["name"], "uid": n["metadata"]["uid"]} for n in nodes
        ],
        "minimum_ready_nodes": 2,
        "workload": {
            "deployment": {
                "namespace": ns,
                "object": {"name": "orders-fixture", "uid": deployment["metadata"]["uid"]},
            },
            "generation": deployment["metadata"]["generation"],
            "replica_set": {
                "name": replica_set["metadata"]["name"],
                "uid": replica_set["metadata"]["uid"],
            },
            "pdb": {"name": "orders-fixture", "uid": pdb["metadata"]["uid"]},
            "pdb_generation": pdb["metadata"]["generation"],
            "pdb_min_available": 2,
            "minimum_available": 2,
        },
        "allowed_daemon_sets": daemon_sets,
        "allowed_mirror_pods": [],
        "maximum_pods": 8,
        "maximum_requests": 16,
        "maximum_deferred_ms": 60000,
        "grace_period_seconds": 1,
    }
    stem = ns + "-read"
    read_rules = [
        {
            "apiGroups": [""],
            "resources": ["nodes"],
            "verbs": ["get"],
            "resourceNames": [n["metadata"]["name"] for n in nodes],
        },
        {
            "apiGroups": [""],
            "resources": ["namespaces"],
            "verbs": ["get"],
            "resourceNames": ["kube-system"],
        },
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
    ]
    items = [
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": stem, "labels": {"kedgeflow.dev/fixture-owner": args.cluster}},
            "rules": read_rules,
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": stem},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": stem,
            },
            "subjects": [
                {"kind": "ServiceAccount", "name": n, "namespace": ns}
                for n in ["mutator", "observer"]
            ],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": ns + "-patch"},
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["nodes"],
                    "verbs": ["patch"],
                    "resourceNames": [target],
                }
            ],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": ns + "-patch"},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": ns + "-patch",
            },
            "subjects": [{"kind": "ServiceAccount", "name": "mutator", "namespace": ns}],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "read-workload", "namespace": ns},
            "rules": [
                {
                    "apiGroups": ["apps"],
                    "resources": ["deployments"],
                    "resourceNames": ["orders-fixture"],
                    "verbs": ["get"],
                },
                {
                    "apiGroups": ["apps"],
                    "resources": ["replicasets"],
                    "resourceNames": [replica_set["metadata"]["name"]],
                    "verbs": ["get"],
                },
                {
                    "apiGroups": ["policy"],
                    "resources": ["poddisruptionbudgets"],
                    "resourceNames": ["orders-fixture"],
                    "verbs": ["get"],
                },
            ],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "read-workload", "namespace": ns},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "read-workload",
            },
            "subjects": [
                {"kind": "ServiceAccount", "name": n, "namespace": ns}
                for n in ["mutator", "observer"]
            ],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "evict-original", "namespace": ns},
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["pods/eviction"],
                    "verbs": ["create"],
                    "resourceNames": [selected[0]["metadata"]["name"]],
                }
            ],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "evict-original", "namespace": ns},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "evict-original",
            },
            "subjects": [{"kind": "ServiceAccount", "name": "mutator", "namespace": ns}],
        },
    ]
    kubectl("create", "-f", "-", value={"apiVersion": "v1", "kind": "List", "items": items})
    for name in ["mutator", "observer"]:
        save(
            name + ".token",
            kubectl("create", "token", name, "-n", ns, "--duration=1h").strip().encode(),
        )
    save("contract.json", (json.dumps(contract, indent=2) + "\n").encode())
    public = {
        "profile": contract["profile"],
        "cluster": args.cluster,
        "namespace": ns,
        "target_node": target,
        "nodes": [
            {"name": n["metadata"]["name"], "uid": n["metadata"]["uid"],
             "kubelet_version": n["status"]["nodeInfo"]["kubeletVersion"],
             "container_runtime_version": n["status"]["nodeInfo"]["containerRuntimeVersion"]}
            for n in nodes
        ],
        "original_pod": {
            "name": selected[0]["metadata"]["name"],
            "uid": selected[0]["metadata"]["uid"],
        },
        "image": {
            "reference": "registry.k8s.io/pause:3.10",
            "pull_policy": "Never",
            "actual_image_ids": sorted(
                {c["imageID"] for p in pods for c in p["status"]["containerStatuses"]}
            ),
            "scope": "preloaded by pinned kind node image; "
                     "fixture readiness gates only, no application SLO",
        },
    }
    save("fixture-public.json", (json.dumps(public, indent=2) + "\n").encode())
    print(
        json.dumps(
            {
                "status": "ready",
                "output": str(out),
                "namespace": ns,
                "target": target,
                "scope": "owned isolated kind fixture; "
                 "generated SA credentials remain private files",
            }
        )
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ["kubectl", "kubeconfig", "output"]:
        p.add_argument("--" + name, required=True, type=Path)
    for name in ["cluster", "context", "namespace"]:
        p.add_argument("--" + name, required=True)
    run(p.parse_args())

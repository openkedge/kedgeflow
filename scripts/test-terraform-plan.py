#!/usr/bin/env python3
"""Generate a real saved plan using an owned kind ConfigMap.

The default path only inspects with a get-only token. An explicit execution
command selects the v0.2 native-runner fixture. Public outputs are sanitized;
private plans, state, credentials and tool snapshots are removed.
"""

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    if not re.fullmatch(r"kind-kf8-[a-z0-9-]+", args.context):
        raise ValueError("explicit owned kind context required")
    kubectl = [
        str(args.kubectl.resolve()),
        "--kubeconfig",
        str(args.kubeconfig.resolve()),
        "--context",
        args.context,
        "--request-timeout=10s",
    ]
    args.output.mkdir(parents=True, exist_ok=False)
    steps = []

    active_child = args.active_child
    execution = bool(args.execution_command)
    if active_child and (
        not execution or args.pair_inspector or not args.docker or not args.audit_node
    ):
        raise ValueError(
            "active-child qualification requires explicit single execution and owned audit node"
        )
    if active_child and not re.fullmatch(r"kf8-tfpa[a-z0-9-]*-control-plane", args.audit_node):
        raise ValueError("owned audit node required")
    if active_child and bool(args.expect_effect) != (active_child == "deadline-late"):
        raise ValueError("active-child effect expectation mismatch")
    pair = bool(args.pair_inspector)
    pair_execution = args.pair_execution
    if pair_execution and (not pair or not execution):
        raise ValueError("pair execution requires explicit pair inspector and native command")
    if pair_execution and (
        not args.docker
        or not args.audit_node
        or not re.fullmatch(r"kf8-tfpa[a-z0-9-]*-control-plane", args.audit_node)
    ):
        raise ValueError("pair execution requires the explicit owned audit node and Docker client")
    if pair and (
        (execution and not pair_execution) or args.expect_effect or args.expect_external_revision
    ):
        raise ValueError("pair inspection is read-only and cannot select execution")
    if pair and not args.inspector:
        raise ValueError("pair inspection requires the legacy inspector for refusal checks")
    inspector = args.pair_inspector or args.inspector
    live_backend = execution or pair
    if args.expect_effect and not execution:
        raise ValueError("effect expectation requires explicit execution qualification")
    if args.expect_external_revision and (not execution or args.expect_effect):
        raise ValueError("external target injection requires an unchanged-effect execution case")

    def command(label, argv, body=None, env=None, cwd=None, expected=0, timeout=90):
        result = subprocess.run(
            argv,
            input=body,
            capture_output=True,
            text=True,
            env=env,
            cwd=cwd,
            timeout=timeout,
            umask=0o077,
        )
        steps.append({"step": label, "exit_code": result.returncode})
        if label == "native admission to original Terraform execution" or (
            label == "protected saved-plan inspection" and result.returncode != expected
        ):
            diagnostic = result.stdout + result.stderr
            for secret in [token, writer]:
                if secret:
                    diagnostic = diagnostic.replace(secret, "[redacted-fixture-token]")
            diagnostic = re.sub(
                r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
                "[redacted-fixture-token]",
                diagnostic,
            )
            filename = (
                "execution-diagnostic.log"
                if label == "native admission to original Terraform execution"
                else "inspection-diagnostic.log"
            )
            (args.output / filename).write_text(diagnostic)
        if result.returncode != expected:
            # Terraform diagnostics and configuration may contain credentials.
            raise RuntimeError(f"{label}: unexpected exit {result.returncode}")
        return result.stdout

    namespace = "kf-tf-plan-" + os.urandom(8).hex()
    target = "target-first" if pair else "target"
    ns_uid = None
    token = None
    writer = None
    gate = None
    with tempfile.TemporaryDirectory(prefix="kf-tf-plan-") as temporary:
        private = Path(temporary).resolve()

        def write(name, value):
            path = private / name
            path.write_text(json.dumps(value) if not isinstance(value, str) else value)
            path.chmod(0o600)
            return path

        def kube(label, *argv, body=None):
            return command(label, [*kubectl, *argv], body=body)

        try:
            version = json.loads(
                command(
                    "pin Terraform version",
                    [str(args.terraform.resolve()), "version", "-json"],
                    env={"CHECKPOINT_DISABLE": "1", "PATH": "/usr/bin:/bin"},
                )
            )
            platform = version["platform"]
            if version["terraform_version"] != "1.17.1" or platform not in (
                "darwin_arm64",
                "darwin_amd64",
                "linux_arm64",
                "linux_amd64",
            ):
                raise ValueError("pinned Terraform 1.17.1 platform required")
            connection = json.loads(
                kube(
                    "owned cluster configuration",
                    "config",
                    "view",
                    "--minify",
                    "--raw",
                    "-o",
                    "json",
                )
            )["clusters"][0]["cluster"]
            if urlparse(connection["server"]).hostname != "127.0.0.1":
                raise ValueError("owned loopback kind API required")
            cluster_uid = kube(
                "cluster incarnation",
                "get",
                "namespace",
                "kube-system",
                "-o",
                "jsonpath={.metadata.uid}",
            )
            body = {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": namespace,
                    "labels": {"kedgeflow.dev/terraform-plan-fixture": namespace},
                },
            }
            ns_uid = json.loads(
                kube(
                    "create owned namespace",
                    "create",
                    "-f",
                    "-",
                    "-o",
                    "json",
                    body=json.dumps(body),
                )
            )["metadata"]["uid"]
            objects = [
                {
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {
                        "name": target,
                        "namespace": namespace,
                        "annotations": {"kedgeflow.dev/revision": "before"},
                    },
                    "data": {"fixed": "fixture"},
                },
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {"name": "planner", "namespace": namespace},
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "Role",
                    "metadata": {"name": "planner", "namespace": namespace},
                    "rules": [
                        {
                            "apiGroups": [""],
                            "resources": ["configmaps"],
                            "resourceNames": [target, "target-second"] if pair else [target],
                            "verbs": ["get"],
                        }
                    ],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {"name": "planner", "namespace": namespace},
                    "roleRef": {
                        "apiGroup": "rbac.authorization.k8s.io",
                        "kind": "Role",
                        "name": "planner",
                    },
                    "subjects": [
                        {"kind": "ServiceAccount", "name": "planner", "namespace": namespace}
                    ],
                },
            ]
            if pair:
                second = copy.deepcopy(objects[0])
                second["metadata"]["name"] = "target-second"
                objects.insert(1, second)
            if execution:
                objects.extend(
                    [
                        {
                            "apiVersion": "v1",
                            "kind": "ServiceAccount",
                            "metadata": {"name": "runner", "namespace": namespace},
                        },
                        {
                            "apiVersion": "rbac.authorization.k8s.io/v1",
                            "kind": "Role",
                            "metadata": {"name": "runner", "namespace": namespace},
                            "rules": [
                                {
                                    "apiGroups": [""],
                                    "resources": ["configmaps"],
                                    "resourceNames": [target],
                                    "verbs": ["get", "patch", "update"],
                                }
                            ],
                        },
                        {
                            "apiVersion": "rbac.authorization.k8s.io/v1",
                            "kind": "RoleBinding",
                            "metadata": {"name": "runner", "namespace": namespace},
                            "roleRef": {
                                "apiGroup": "rbac.authorization.k8s.io",
                                "kind": "Role",
                                "name": "runner",
                            },
                            "subjects": [
                                {"kind": "ServiceAccount", "name": "runner", "namespace": namespace}
                            ],
                        },
                    ]
                )
            if pair_execution:
                role = next(
                    o for o in objects if o["kind"] == "Role" and o["metadata"]["name"] == "runner"
                )
                role["rules"] = [
                    {
                        "apiGroups": [""],
                        "resources": ["configmaps"],
                        "resourceNames": [target, "target-second"],
                        "verbs": ["get"],
                    },
                    {
                        "apiGroups": [""],
                        "resources": ["configmaps"],
                        "resourceNames": [target]
                        if pair_execution == "partial"
                        else [target, "target-second"],
                        "verbs": ["patch", "update"],
                    },
                ]
            kube(
                "seed ConfigMap and read-only planner",
                "create",
                "-f",
                "-",
                body=json.dumps({"apiVersion": "v1", "kind": "List", "items": objects}),
            )
            token = kube(
                "mint get-only planner token",
                "create",
                "token",
                "planner",
                "-n",
                namespace,
                "--duration=10m",
            ).strip()
            reader = write(
                "reader.json",
                {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "clusters": [{"name": "owned", "cluster": connection}],
                    "contexts": [
                        {
                            "name": "reader",
                            "context": {
                                "cluster": "owned",
                                "user": "reader",
                                "namespace": namespace,
                            },
                        }
                    ],
                    "current-context": "reader",
                    "users": [{"name": "reader", "user": {"token": token}}],
                },
            )
            command(
                "planner cannot patch ConfigMaps",
                [
                    str(args.kubectl.resolve()),
                    "--kubeconfig",
                    str(reader),
                    "--context",
                    "reader",
                    "--request-timeout=10s",
                    "auth",
                    "can-i",
                    "patch",
                    "configmaps",
                    "-n",
                    namespace,
                    "--quiet",
                ],
                expected=1,
            )
            observed = json.loads(
                kube("observe baseline", "get", "configmap", target, "-n", namespace, "-o", "json")
            )
            observed_second = (
                json.loads(
                    kube(
                        "observe second baseline",
                        "get",
                        "configmap",
                        "target-second",
                        "-n",
                        namespace,
                        "-o",
                        "json",
                    )
                )
                if pair
                else None
            )
            mirror = (
                private / f"mirror/registry.terraform.io/hashicorp/kubernetes/2.38.0/{platform}"
            )
            mirror.mkdir(parents=True)
            shutil.copyfile(args.provider, mirror / "terraform-provider-kubernetes_v2.38.0_x5")
            (mirror / "terraform-provider-kubernetes_v2.38.0_x5").chmod(0o700)
            rc = write(
                "terraform.rc",
                f"disable_checkpoint = true\nprovider_installation {{\n"
                f' filesystem_mirror {{ path = "{private / "mirror"}" }}\n}}\n',
            )
            if active_child:
                from terraform_active_gate import ActiveGate

                gate = ActiveGate(private, connection, namespace, target)
                connection = gate.connection
            config = {
                "terraform": {
                    "required_providers": {
                        "kubernetes": {"source": "hashicorp/kubernetes", "version": "=2.38.0"}
                    }
                },
                "provider": {
                    "kubernetes": {
                        "host": connection["server"],
                        "token": token,
                        "cluster_ca_certificate": base64.b64decode(
                            connection["certificate-authority-data"]
                        ).decode(),
                    }
                },
                "resource": {
                    "kubernetes_config_map_v1": {
                        "target": {
                            "metadata": {
                                "name": target,
                                "namespace": namespace,
                                "annotations": {"kedgeflow.dev/revision": "after"},
                            },
                            "data": {"fixed": "fixture"},
                        }
                    }
                },
            }
            state_path = private / "terraform.tfstate"
            if live_backend:
                backend_root = private / "backend"
                backend_root.mkdir(mode=0o700)
                state_path = backend_root / "terraform.tfstate"
                config["terraform"]["backend"] = {"local": {"path": str(state_path)}}
                del config["provider"]["kubernetes"]["token"]
            if pair:
                first = config["resource"]["kubernetes_config_map_v1"].pop("target")
                second = copy.deepcopy(first)
                second["metadata"]["name"] = "target-second"
                second["depends_on"] = ["kubernetes_config_map_v1.first"]
                config["resource"]["kubernetes_config_map_v1"] = {"first": first, "second": second}
            write("main.tf.json", config)
            env = {
                "TF_CLI_CONFIG_FILE": str(rc),
                "TF_IN_AUTOMATION": "1",
                "CHECKPOINT_DISABLE": "1",
                "PATH": "/usr/bin:/bin",
            }
            if live_backend:
                env["KUBE_TOKEN"] = token
            terraform = [str(args.terraform.resolve())]
            command(
                "offline provider initialization",
                [*terraform, "init", "-input=false", "-no-color"],
                env=env,
                cwd=private,
            )
            command(
                "read-only import baseline",
                [
                    *terraform,
                    "import",
                    "-input=false",
                    "-no-color",
                    "kubernetes_config_map_v1.first" if pair else "kubernetes_config_map_v1.target",
                    f"{namespace}/{target}",
                ],
                env=env,
                cwd=private,
            )
            if pair:
                command(
                    "read-only second import",
                    [
                        *terraform,
                        "import",
                        "-input=false",
                        "-no-color",
                        "kubernetes_config_map_v1.second",
                        f"{namespace}/target-second",
                    ],
                    env=env,
                    cwd=private,
                )
            command(
                "save refreshed plan",
                [*terraform, "plan", "-input=false", "-no-color", "-out=plan.bin"],
                env=env,
                cwd=private,
            )
            raw = command(
                "derive JSON from saved plan",
                [*terraform, "show", "-json", "plan.bin"],
                env=env,
                cwd=private,
            )
            capsule = private / "capsule"
            capsule.mkdir(mode=0o700)
            for name, source in {
                "terraform.bin": args.terraform,
                "kubernetes.bin": args.provider,
                "plan.bin": private / "plan.bin",
                "state.json": state_path,
                "lock.hcl": private / ".terraform.lock.hcl",
                "configuration.json": private / "main.tf.json",
            }.items():
                shutil.copyfile(source, capsule / name)
                (capsule / name).chmod(0o600)
            if live_backend:
                shutil.copyfile(private / ".terraform/terraform.tfstate", capsule / "backend.json")
                (capsule / "backend.json").chmod(0o600)
            manifest = {
                "profile": "KF-TERRAFORM-PLAN-0.2-draft"
                if live_backend
                else "KF-TERRAFORM-PLAN-0.1-draft",
                "terraform_version": "1.17.1",
                "provider_version": "2.38.0",
                "platform": platform,
                "workspace_id": "owned:" + namespace,
                "backend": "local",
                "target": {
                    "cluster_uid": cluster_uid,
                    "namespace": namespace,
                    "name": target,
                    "uid": observed["metadata"]["uid"],
                    "resource_version": observed["metadata"]["resourceVersion"],
                },
                "before_revision": "before",
                "after_revision": "after",
                "files": {p.name: sha(p) for p in capsule.iterdir()},
            }
            if live_backend:
                manifest["backend_state_path"] = str(state_path)
            if pair:
                manifest["profile"] = "KF-TERRAFORM-PAIR-PLAN-0.1-draft"
                first = {
                    "id": "first",
                    "target": manifest.pop("target"),
                    "before_revision": manifest.pop("before_revision"),
                    "after_revision": manifest.pop("after_revision"),
                }
                second = copy.deepcopy(first)
                second["id"] = "second"
                second["target"].update(
                    name="target-second",
                    uid=observed_second["metadata"]["uid"],
                    resource_version=observed_second["metadata"]["resourceVersion"],
                )
                manifest["members"] = [first, second]
            (capsule / "manifest.json").write_text(json.dumps(manifest))
            (capsule / "manifest.json").chmod(0o600)
            # Publish only redacted semantic fixtures, not executable plan bytes.
            for name, value in {
                "inspection.json": json.loads(raw),
                "state.json": json.loads(state_path.read_text()),
                "configuration.json": config,
                "manifest.json": manifest,
            }.items():
                (args.output / name).write_text(
                    json.dumps(value, indent=2).replace(token, "fixture-readonly-token") + "\n"
                )
            if inspector:
                report = json.loads(
                    command(
                        "protected saved-plan inspection",
                        [
                            str(inspector.resolve()),
                            "--material-root",
                            str(capsule),
                            "--manifest",
                            str(capsule / "manifest.json"),
                        ],
                    )
                )
                (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
                assert report["status"] == "inspection_passed"
                assert report["execution_enabled"] is False
                assert report["guard_level"] == "Level_C"
                inspect = [
                    str(inspector.resolve()),
                    "--material-root",
                    str(capsule),
                    "--manifest",
                    str(capsule / "manifest.json"),
                ]
                isolated = json.loads(
                    command(
                        "ignore ambient Terraform overrides",
                        inspect,
                        env={
                            **os.environ,
                            "TF_CLI_ARGS_show": "-must-not-reach-terraform",
                            "TF_DATA_DIR": "/must-not-use-ambient-data",
                            "TF_LOG": "TRACE",
                        },
                    )
                )
                assert isolated["manifest_digest"] == report["manifest_digest"]
                assert isolated["effect_digest"] == report["effect_digest"]
                original = (capsule / "plan.bin").read_bytes()
                (capsule / "plan.bin").write_bytes(original + b"\0")
                command("refuse swapped saved plan", inspect, expected=1)
                (capsule / "plan.bin").write_bytes(original)
                original_config = (capsule / "configuration.json").read_bytes()
                unsafe = json.loads(original_config)
                unsafe["provider"]["kubernetes"]["exec"] = {"command": "false"}
                (capsule / "configuration.json").write_text(json.dumps(unsafe))
                manifest["files"]["configuration.json"] = sha(capsule / "configuration.json")
                (capsule / "manifest.json").write_text(json.dumps(manifest))
                command("refuse pinned executable provider hook", inspect, expected=1)
                (capsule / "configuration.json").write_bytes(original_config)
                manifest["files"]["configuration.json"] = sha(capsule / "configuration.json")
                (capsule / "manifest.json").write_text(json.dumps(manifest))
                command("no apply entry point", [*inspect, "--apply"], expected=2)
                if pair:
                    command(
                        "single-resource inspector refuses pair profile",
                        [str(args.inspector.resolve()), *inspect[1:]],
                        expected=1,
                    )
                    with zipfile.ZipFile(private / "plan.bin") as plan_zip:
                        assert all(
                            token.encode() not in plan_zip.read(n) for n in plan_zip.namelist()
                        )
            if execution:
                assert token not in raw
                with zipfile.ZipFile(private / "plan.bin") as plan_zip:
                    assert all(token.encode() not in plan_zip.read(n) for n in plan_zip.namelist())
                secrets = private / "secrets"
                secrets.mkdir(mode=0o700)
                writer = kube(
                    "mint runner-only writer token",
                    "create",
                    "token",
                    "runner",
                    "-n",
                    namespace,
                    "--duration=10m",
                ).strip()
                for name, value in [("observer.token", token), ("writer.token", writer)]:
                    (secrets / name).write_text(value)
                    (secrets / name).chmod(0o600)
                output = command(
                    "native admission to original Terraform execution",
                    args.execution_command,
                    env={
                        **os.environ,
                        "KF_REQUIRE_TERRAFORM": "1",
                        "KF_TERRAFORM_CAPSULE": str(capsule),
                        "KF_TERRAFORM_BACKEND_ROOT": str(backend_root),
                        "KF_TERRAFORM_SECRET_ROOT": str(secrets),
                        "KF_TERRAFORM_TEST_PUBLIC_OUTPUT": str(args.output.resolve()),
                        "KF_TERRAFORM_KUBECTL": str(args.kubectl.resolve()),
                        "KF_TERRAFORM_KUBECONFIG": str(args.kubeconfig.resolve()),
                        "KF_TERRAFORM_CONTEXT": args.context,
                        "KF_TERRAFORM_DOCKER": str(args.docker.resolve()) if args.docker else "",
                        "KF_TERRAFORM_AUDIT_NODE": args.audit_node or "",
                        "KF_TERRAFORM_ACTIVE_GATE_DIR": str(gate.root) if gate else "",
                    },
                    cwd=Path(__file__).resolve().parents[1],
                    timeout=300,
                )
                assert token not in output and writer not in output
                (args.output / "execution.log").write_text(output)
                if pair_execution:
                    original_bytes = (capsule / "state.json").read_bytes()
                    final_bytes = state_path.read_bytes()
                    original_state = json.loads(original_bytes)
                    final_state = json.loads(final_bytes)
                    assert final_state["lineage"] == original_state["lineage"]
                    assert final_state["serial"] > original_state["serial"]
                    assert len(final_state["resources"]) == 2
                    members = []
                    raw_targets = []
                    for index, name in enumerate([target, "target-second"]):
                        member = final_state["resources"][index]
                        assert member["name"] == ["first", "second"][index]
                        metadata = member["instances"][0]["attributes"]["metadata"][0]
                        assert metadata["uid"] == manifest["members"][index]["target"]["uid"]
                        provider_revision = metadata["annotations"]["kedgeflow.dev/revision"]
                        assert provider_revision in ("before", "after")
                        if index == 0 or pair_execution == "normal":
                            assert provider_revision == "after"
                        members.append(
                            {
                                "id": member["name"],
                                "uid": metadata["uid"],
                                "revision": provider_revision,
                                "resource_version": metadata["resource_version"],
                            }
                        )
                        raw_target = json.loads(
                            command(
                                "independent raw member observation",
                                [
                                    str(args.kubectl.resolve()),
                                    "--kubeconfig",
                                    str(reader),
                                    "--context",
                                    "reader",
                                    "get",
                                    "--raw",
                                    f"/api/v1/namespaces/{namespace}/configmaps/{name}",
                                ],
                            )
                        )
                        raw_targets.append({"id": member["name"], "object": raw_target})
                    (args.output / "backend-observation.json").write_text(
                        json.dumps(
                            {
                                "before": {
                                    "sha256": hashlib.sha256(original_bytes).hexdigest(),
                                    "lineage": original_state["lineage"],
                                    "serial": original_state["serial"],
                                },
                                "after": {
                                    "sha256": hashlib.sha256(final_bytes).hexdigest(),
                                    "lineage": final_state["lineage"],
                                    "serial": final_state["serial"],
                                },
                                "members": members,
                            },
                            indent=2,
                        )
                        + "\n"
                    )
                    (args.output / "target-raw-observation.json").write_text(
                        json.dumps({"members": raw_targets}, indent=2) + "\n"
                    )
            after = json.loads(
                kube(
                    "independent final target",
                    "get",
                    "configmap",
                    target,
                    "-n",
                    namespace,
                    "-o",
                    "json",
                )
            )
            if pair_execution:
                assert after["metadata"]["uid"] == observed["metadata"]["uid"]
                assert after["metadata"]["annotations"] == {"kedgeflow.dev/revision": "after"}
                assert (
                    after["metadata"]["resourceVersion"] != observed["metadata"]["resourceVersion"]
                )
                for key in ("data", "binaryData", "immutable"):
                    assert after.get(key) == observed.get(key)
                assert after["metadata"].get("labels") == observed["metadata"].get("labels")
            elif args.expect_effect:
                assert execution and after["metadata"]["uid"] == observed["metadata"]["uid"]
                assert after["data"] == observed["data"] and after["metadata"]["annotations"] == {
                    "kedgeflow.dev/revision": "after"
                }
                assert (
                    after["metadata"]["resourceVersion"] != observed["metadata"]["resourceVersion"]
                )
            elif args.expect_external_revision:
                assert after["metadata"]["uid"] == observed["metadata"]["uid"]
                for field in ["data", "binaryData", "immutable"]:
                    assert after.get(field) == observed.get(field)
                assert after["metadata"].get("labels") == observed["metadata"].get("labels")
                assert after["metadata"]["annotations"] == {
                    "kedgeflow.dev/revision": args.expect_external_revision
                }
                assert (
                    after["metadata"]["resourceVersion"] != observed["metadata"]["resourceVersion"]
                )
            else:
                assert after == observed, "unadmitted ConfigMap effect"
            if pair:
                after_second = json.loads(
                    kube(
                        "independent second final target",
                        "get",
                        "configmap",
                        "target-second",
                        "-n",
                        namespace,
                        "-o",
                        "json",
                    )
                )
                if pair_execution == "normal":
                    assert after_second["metadata"]["uid"] == observed_second["metadata"]["uid"]
                    assert after_second["metadata"]["annotations"] == {
                        "kedgeflow.dev/revision": "after"
                    }
                    assert (
                        after_second["metadata"]["resourceVersion"]
                        != observed_second["metadata"]["resourceVersion"]
                    )
                    for key in ("data", "binaryData", "immutable"):
                        assert after_second.get(key) == observed_second.get(key)
                    assert after_second["metadata"].get("labels") == observed_second[
                        "metadata"
                    ].get("labels")
                else:
                    assert after_second == observed_second, "unadmitted second ConfigMap effect"
                (args.output / "target-observation.json").write_text(
                    json.dumps(
                        {
                            "members": [
                                {"id": "first", "before": observed, "after": after},
                                {"id": "second", "before": observed_second, "after": after_second},
                            ]
                        },
                        indent=2,
                    )
                    + "\n"
                )
            elif execution:
                (args.output / "target-observation.json").write_text(
                    json.dumps({"before": observed, "after": after}, indent=2) + "\n"
                )
        finally:
            if gate:
                gate.close()
                (args.output / "gate-requests.json").write_text(
                    json.dumps(gate.requests, indent=2) + "\n"
                )
            if ns_uid:
                current = json.loads(
                    kube("verify cleanup ownership", "get", "namespace", namespace, "-o", "json")
                )
                assert current["metadata"]["uid"] == ns_uid
                assert (
                    current["metadata"]["labels"]["kedgeflow.dev/terraform-plan-fixture"]
                    == namespace
                )
                kube(
                    "cleanup owned namespace",
                    "delete",
                    "namespace",
                    namespace,
                    "--wait=true",
                    "--timeout=60s",
                )
            (args.output / "steps.json").write_text(json.dumps(steps, indent=2) + "\n")
            if token:
                assert all(token not in p.read_text() for p in args.output.iterdir())
            if writer:
                assert all(writer not in p.read_text() for p in args.output.iterdir())
    print(
        json.dumps(
            {
                "status": "passed",
                "scope": "native Terraform execution qualification"
                if execution
                else "saved-plan inspection; no Terraform apply",
                "steps": len(steps),
                "output": str(args.output),
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["terraform", "provider", "kubectl", "kubeconfig", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--inspector", type=Path)
    parser.add_argument(
        "--active-child", choices=["provider-kill", "terraform-kill", "deadline-late"]
    )
    parser.add_argument("--pair-inspector", type=Path)
    parser.add_argument("--pair-execution", choices=["normal", "partial"])
    parser.add_argument("--docker", type=Path)
    parser.add_argument("--audit-node")
    parser.add_argument("--expect-effect", action="store_true")
    parser.add_argument("--expect-external-revision", choices=["external"])
    argv = sys.argv[1:]
    execution_command = None
    if "--execution-command" in argv:
        index = argv.index("--execution-command")
        execution_command = argv[index + 1 :]
        argv = argv[:index]
        if not execution_command:
            parser.error("execution command required")
    args = parser.parse_args(argv)
    args.execution_command = execution_command
    run(args)

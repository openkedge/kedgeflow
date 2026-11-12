#!/usr/bin/env python3
"""Root-only adapter for an explicitly disposable Terraform/systemd fixture.

This helper is not installed in the runtime bundle. Only the trusted fixture
controller has sudo access; the SDK agent has a separate unprivileged UID.
"""

import argparse
import hashlib
import json
import os
import pwd
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


def run(args, check=True, **kw):
    result = subprocess.run(
        list(map(str, args)), capture_output=True, text=True, check=False, timeout=90, **kw
    )
    if check and result.returncode:
        raise RuntimeError(f"fixture command failed ({result.returncode}): {result.stderr}")
    return result


def props(unit):
    keys = [
        "MainPID",
        "ActiveState",
        "SubState",
        "ControlGroup",
        "ExecMainCode",
        "ExecMainStatus",
        "NRestarts",
        "KillMode",
        "TimeoutStopUSec",
        "NoNewPrivileges",
        "ProtectSystem",
        "ProtectControlGroups",
        "RestrictNamespaces",
        "PrivateTmp",
        "User",
        "CapabilityBoundingSet",
        "Delegate",
    ]
    r = run(["systemctl", "show", unit, *["--property=" + k for k in keys]])
    return dict(x.split("=", 1) for x in r.stdout.splitlines() if "=" in x)


def process(pid):
    p = Path("/proc") / str(pid)
    if not p.exists():
        return None
    try:
        status = dict(x.split(":", 1) for x in (p / "status").read_text().splitlines() if ":" in x)
        if status["State"].strip().startswith("Z"):
            return None
        return {
            "pid": pid,
            "uid": int(status["Uid"].split()[1]),
            "pgid": os.getpgid(pid),
            "exe": Path(os.readlink(p / "exe")).name,
            "cgroup": (p / "cgroup").read_text().strip(),
            "cap_eff": status["CapEff"].strip(),
            "no_new_privs": status.get("NoNewPrivs", "").strip(),
            "seccomp": status.get("Seccomp", "").strip(),
        }
    except (FileNotFoundError, ProcessLookupError):
        return None


def cgpids(group):
    p = Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.procs"
    return [int(x) for x in p.read_text().split()] if p.exists() else []


def main():
    if "--escape" in sys.argv:
        marker = Path(sys.argv[-1])
        pid = os.fork()
        if pid:
            return
        os.setsid()
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        marker.write_text(
            json.dumps({"pid": os.getpid(), "pgid": os.getpgrp(), "uid": os.getuid()})
        )
        for _ in range(240):
            time.sleep(1)
        os._exit(0)
    p = argparse.ArgumentParser()
    p.add_argument("--state", type=Path, required=True)
    p.add_argument(
        "--action",
        required=True,
        choices=[
            "start",
            "stop",
            "status",
            "node",
            "retained",
            "writer-remove",
            "kill-main",
            "audit",
        ],
    )
    p.add_argument("--material", type=Path, required=True)
    p.add_argument("--config", type=Path)
    a = p.parse_args()
    assert os.geteuid() == 0 and Path("/proc/1/comm").read_text().strip() == "systemd"
    st = a.state.stat()
    assert st.st_uid == 0 and st.st_mode & 0o777 == 0o600 and not a.state.is_symlink()
    s = json.loads(a.state.read_text())
    base = Path(s["base"])
    assert base.parent == Path("/run") and base.name.startswith("kf-tflinux-")
    material = a.material.resolve()
    assert (
        material.is_relative_to(base / "work") and material.is_dir() and not a.material.is_symlink()
    )
    key = hashlib.sha256(str(material).encode()).hexdigest()[:16]
    unit = "kf-tfi-" + key + ".service"
    unitpath = Path("/etc/systemd/system") / unit
    record = base / ("case-" + key + ".json")
    agent = base / ("agent-" + key)
    identity = pwd.getpwnam(s["gateway_user"])
    agentid = pwd.getpwnam(s["agent_user"])
    assert identity.pw_uid > 0 and agentid.pw_uid > 0 and identity.pw_uid != agentid.pw_uid
    if a.action == "audit":
        out = run(
            [
                "/usr/bin/docker",
                "exec",
                s["audit_node"],
                "cat",
                "/var/log/kubernetes/kube-apiserver-audit.log",
            ]
        )
        print(out.stdout, end="")
        return
    if a.action == "node":
        assert a.config and a.config.resolve().parent == material
        v = json.loads(a.config.read_text())
        agent.mkdir(mode=0o700, exist_ok=True)
        os.chown(agent, agentid.pw_uid, agentid.pw_gid)
        v["storeDirectory"] = str(agent / "operations")
        conf = agent / "config.json"
        conf.write_text(json.dumps(v))
        conf.chmod(0o400)
        os.chown(conf, agentid.pw_uid, agentid.pw_gid)
        out = run(
            [
                "runuser",
                "-u",
                s["agent_user"],
                "--",
                "env",
                "-i",
                "PATH=" + s["node_dir"] + ":/usr/bin:/bin",
                "KF_SYSTEMD_AGENT_UID=" + str(agentid.pw_uid),
                "KF_SYSTEMD_AGENT_GID=" + str(agentid.pw_gid),
                s["node_dir"] + "/node",
                s["source"] + "/tests/sdk/live-agent.mjs",
                conf,
            ]
        )
        print(out.stdout, end="")
        return
    if a.action == "retained":
        files = list((agent / "operations").glob("*.json"))
        assert len(files) == 1
        print(files[0].read_text())
        return
    if a.action == "writer-remove":
        v = json.loads((material / "gateway.json").read_text())
        path = Path(v["terraform_adapter"]["pins"]["writer_token_file"])
        assert path.is_relative_to(base / "work")
        path.rename(path.with_name("writer.saved"))
        print("{}")
        return
    if a.action == "stop":
        if unitpath.exists():
            run(["systemctl", "stop", unit])
            run(["systemctl", "reset-failed", unit], check=False)
        print("{}")
        return
    if a.action == "status":
        v = props(unit)
        print(
            json.dumps(
                {
                    "active": v.get("ActiveState") in ["active", "activating", "deactivating"],
                    "properties": v,
                }
            )
        )
        return
    if a.action == "start":
        assert a.config and a.config.resolve() == material / "gateway.json"
        v = json.loads(a.config.read_text())
        pins = v["terraform_adapter"]["pins"]
        staging = base / "work" / ("staging-" + key)
        staging.mkdir(mode=0o700, exist_ok=True)
        os.chown(staging, identity.pw_uid, identity.pw_gid)
        for name in ["material_root", "backend_root", "secret_root"]:
            assert Path(pins[name]).resolve().is_relative_to(base / "work")
        command = [
            s["bin_dir"] + "/kf-proxy",
            "--config",
            str(a.config),
            "--custody-root",
            str(material),
            "--require-managed",
        ]
        text = Path(
            s["source"] + "/deploy/linux/terraform/kedgeflow-terraform-gateway.service"
        ).read_text()
        text += (
            "\n[Service]\nUser="
            + s["gateway_user"]
            + "\nGroup="
            + s["gateway_user"]
            + "\nStateDirectory=\nReadOnlyPaths=\nReadOnlyPaths="
            + str(material)
            + " "
            + pins["material_root"]
            + " "
            + pins["secret_root"]
            + "\nReadWritePaths=\nReadWritePaths="
            + pins["backend_root"]
            + " "
            + str(staging)
            + "\nEnvironment=TMPDIR="
            + str(staging)
            + "\nExecStartPre=\nExecStart=\nExecStartPre="
            + " ".join(command)
            + " --check\nExecStart="
            + " ".join(command)
            + "\nExecStartPost=/usr/bin/python3 "
            + str(Path(__file__).resolve())
            + " --escape "
            + str(staging / "escaped.json")
            + "\n"
        )
        if unitpath.exists():
            assert record.exists()
            run(["systemctl", "stop", unit])
        unitpath.write_text(text)
        unitpath.chmod(0o644)
        record.write_text(
            json.dumps(
                {"unit": unit, "material": str(material), "pins": pins, "staging": str(staging)}
            )
        )
        run(["systemctl", "daemon-reload"])
        r = run(["systemctl", "start", unit], check=False)
        if r.returncode:
            journal = run(["journalctl", "-u", unit, "--no-pager", "-n", "60"], check=False).stdout
            print(journal, file=sys.stderr)
            raise RuntimeError("protected service failed to start")
        current = props(unit)
        pid = int(current["MainPID"])
        ps = process(pid)
        assert (
            ps
            and ps["uid"] == identity.pw_uid
            and ps["cap_eff"] == "0000000000000000"
            and ps["no_new_privs"] == "1"
            and ps["seccomp"] == "2"
        )
        assert (
            current["KillMode"] == "control-group"
            and current["ProtectSystem"] == "strict"
            and current["NoNewPrivileges"] == "yes"
            and current["ProtectControlGroups"] == "yes"
            and current["Delegate"] == "no"
        )
        probes = []
        writer_path = Path(pins["writer_token_file"])
        if not writer_path.exists():
            writer_path = writer_path.with_name("writer.saved")
        assert writer_path.is_file()
        for label, path in [
            ("writer", str(writer_path)),
            ("plan", pins["manifest_file"]),
            ("gateway_key", v["private_key"]),
            ("process_environment", f"/proc/{pid}/environ"),
            ("docker_socket", "/var/run/docker.sock"),
        ]:
            r = run(
                [
                    "runuser",
                    "-u",
                    s["agent_user"],
                    "--",
                    "python3",
                    "-c",
                    (
                        "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])"
                        if label == "docker_socket"
                        else "import os,sys; fd=os.open(sys.argv[1],os.O_RDONLY); os.close(fd)"
                    ),
                    path,
                ],
                check=False,
            )
            assert Path(path).exists(), label
            assert r.returncode != 0 and "Permission denied" in r.stderr, (label, r.stderr)
            probes.append(
                {
                    "resource": label,
                    "agent_read_refused": True,
                    "errno": "EACCES",
                    "operation": "connect" if label == "docker_socket" else "read",
                }
            )
        # Enter only the real service's mount namespace; run the write probe
        # without privilege as its UID, so ReadOnlyPaths is actually exercised.
        probe = 'import os,sys; p=sys.argv[1]; os.chmod(p,0o600); open(p,"ab").write(b"bad")'
        for label, path in [
            ("plan", pins["manifest_file"]),
            ("writer", str(writer_path)),
            ("configuration", str(a.config)),
        ]:
            r = run(
                [
                    "nsenter",
                    "-t",
                    str(pid),
                    "-m",
                    "--",
                    "setpriv",
                    f"--reuid={identity.pw_uid}",
                    f"--regid={identity.pw_gid}",
                    "--clear-groups",
                    "--no-new-privs",
                    "--bounding-set=-all",
                    "python3",
                    "-c",
                    probe,
                    path,
                ],
                check=False,
            )
            assert r.returncode != 0 and "Read-only file system" in r.stderr, (label, r.stderr)
            probes.append({"resource": label, "service_write_refused": True, "errno": "EROFS"})
        proof = {
            "pid": pid,
            "unit": unit,
            "properties": current,
            "kernel": ps,
            "custody_probes": probes,
        }
        with (base / "output" / "service-starts.jsonl").open("a") as f:
            f.write(json.dumps(proof) + "\n")
        print(
            json.dumps(
                {
                    "pid": pid,
                    "unit": unit,
                    "properties": current,
                    "kernel": ps,
                    "custody_probes": probes,
                }
            )
        )
        return
    assert record.exists()
    case = json.loads(record.read_text())
    v = props(unit)
    pid = int(v["MainPID"])
    before = [process(x) for x in cgpids(v["ControlGroup"])]
    before = [x for x in before if x]
    assert any(x["exe"] == "terraform" for x in before) and any(
        "terraform-provider-kubernetes" in x["exe"] for x in before
    )
    escaped = json.loads((Path(case["staging"]) / "escaped.json").read_text())
    assert any(x["pid"] == escaped["pid"] for x in before)
    assert escaped["pgid"] not in [x["pgid"] for x in before if x["exe"] == "terraform"]
    killed_at = time.time_ns() // 1_000_000
    os.kill(pid, signal.SIGKILL)
    exit_status = None
    empty_at = None
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        state = props(unit)
        if state["ExecMainCode"] == "2" and state["ExecMainStatus"] == "9":
            exit_status = 9
        if all(process(x["pid"]) is None for x in before):
            empty_at = time.time_ns() // 1_000_000
            break
        time.sleep(0.025)
    assert exit_status == 9 and empty_at is not None
    deadline = time.monotonic() + 55
    new = None
    while time.monotonic() < deadline:
        state = props(unit)
        newpid = int(state.get("MainPID", "0"))
        if state["ActiveState"] == "active" and newpid > 0 and newpid != pid:
            try:
                conf = json.loads((material / "gateway.json").read_text())
                host, port = conf["listen"].rsplit(":", 1)
                with socket.create_connection((host, int(port)), timeout=0.2):
                    pass
                new = process(newpid)
                break
            except OSError:
                pass
        time.sleep(0.1)
    assert new and new["uid"] == identity.pw_uid
    print(
        json.dumps(
            {
                "unit": unit,
                "properties": v,
                "old_processes": before,
                "escaped": escaped,
                "exit_status": exit_status,
                "killed_at": killed_at,
                "group_empty_at": empty_at,
                "old_group_empty": True,
                "escaped_process_terminated": process(escaped["pid"]) is None,
                "auto_restart_pid": new["pid"],
                "auto_restart_kernel": new,
                "restart_properties": state,
                "fixture_group_kill": False,
            }
        )
    )


if __name__ == "__main__":
    main()

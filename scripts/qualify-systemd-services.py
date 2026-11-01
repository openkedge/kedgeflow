#!/usr/bin/env python3
"""Temporarily install/test/remove KedgeFlow units on an explicitly disposable systemd VM.

Creates actual test accounts and /opt/kedgeflow, /etc/kedgeflow and unit files;
refuses preexisting names/paths. Generated authority endpoints are reserved closed
loopback sockets. This proves bounded lifecycle/sandbox behavior, not live authority
or production deployment. Cleanup removes only resources created by this fixture.
"""

import argparse
import grp
import hashlib
import json
import os
import platform
import pwd
import runpy
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
ROLES = (
    "gateway",
    "control",
    "broker",
    "sql-target",
    "recovery",
    "collector",
    "operator",
    "governance",
)
LIVE = ("collector", "governance", "recovery", "control", "broker")
FAILED = ("sql-target", "gateway")

PROBE = r"""
import ctypes, errno, json, os, pathlib, sys
canary, outside = map(pathlib.Path,sys.argv[1:])
if sys.flags.optimize:
    raise RuntimeError("sandbox checks require assertions enabled")
lines = pathlib.Path("/proc/self/status").read_text().splitlines()
status = dict(line.split(":",1) for line in lines if ":" in line)
assert os.geteuid() != 0 and int(status["CapEff"].strip(),16) == 0
assert status["NoNewPrivs"].strip() == "1" and status["Seccomp"].strip() == "2"
try:
    with canary.open("ab") as stream: stream.write(b"unexpected")
except OSError as error:
    assert error.errno == errno.EROFS,error
else:
    raise RuntimeError("service filesystem was writable")
assert not outside.exists(),"private temporary directory exposed host canary"
library=ctypes.CDLL(None,use_errno=True)
assert library.unshare(0x10000000) == -1 and ctypes.get_errno() == errno.EPERM
result = {"uid":os.geteuid(),"capabilities":0,"no_new_privileges":True,
          "seccomp_filter":True,"system_files_read_only":True,
          "private_tmp":True,"user_namespace_refused":True}
print("KEDGEFLOW_SANDBOX_PROBE " + json.dumps(result),flush=True)
"""

MONITOR_REQUEST = r"""
import http.client, json, ssl, sys, urllib.parse
url=urllib.parse.urlsplit(sys.argv[1])
context=ssl.create_default_context(cafile=sys.argv[2])
context.load_cert_chain(sys.argv[3],sys.argv[4])
connection=http.client.HTTPSConnection(url.hostname,url.port,context=context,timeout=8)
connection.request("GET",url.path,headers={"Host":url.netloc,"Connection":"close"})
response=connection.getresponse()
raw=response.read(16385)
assert len(raw)<=16384
result={"status":response.status,"cache_control":response.getheader("cache-control")}
if response.status==503: result["report"]=json.loads(raw)
print(json.dumps(result))
connection.close()
"""


def qualify(bundle: Path, expected_sha256: str):
    commands, created_users, installed_units, observations = [], [], [], []
    own_opt = own_config = False
    guards = []
    source_files = [
        Path(__file__),
        ROOT / "scripts/package-linux.py",
        ROOT / "scripts/verify-linux-package.py",
        ROOT / "scripts/linux-preflight-fixture.py",
        *(p for p in (ROOT / "config").rglob("*") if p.is_file()),
    ]
    source_hashes = {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(source_files)
    }
    report = {
        "status": "failed",
        "scope": "disposable installed systemd lifecycle and sandbox smoke",
        "live_authority": False,
        "commands": commands,
        "observations": observations,
    }

    def run(argv, check=True, timeout=45, **kwargs):
        result = subprocess.run(
            [str(arg) for arg in argv],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            **kwargs,
        )
        commands.append(
            {
                "argv": [str(arg) for arg in argv],
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
        if check and result.returncode:
            raise RuntimeError(f"systemd smoke command failed: {argv[0]}: {result.stderr}")
        return result

    def properties(unit):
        result = run(
            [
                "systemctl",
                "show",
                unit,
                "--property=ActiveState,SubState,MainPID,Result,ExecMainStatus,ExecMainCode,InvocationID",
            ]
        )
        return dict(line.split("=", 1) for line in result.stdout.splitlines())

    def await_state(unit, state, deadline=25):
        until = time.monotonic() + deadline
        while time.monotonic() < until:
            value = properties(unit)
            if value["ActiveState"] == state:
                return value
            time.sleep(0.1)
        raise RuntimeError(f"{unit} did not reach {state}")

    try:
        for path in (Path("/opt/kedgeflow"), Path("/etc/kedgeflow")):
            if os.path.lexists(path):
                raise RuntimeError(f"preexisting deployment path: {path}")
        if list(Path("/etc/systemd/system").glob("kedgeflow*")):
            raise RuntimeError("preexisting KedgeFlow units")
        for role in (*ROLES, "fixture-agent"):
            try:
                pwd.getpwnam("kf-" + role)
            except KeyError:
                pass
            else:
                raise RuntimeError("preexisting KedgeFlow account")
            try:
                grp.getgrnam("kf-" + role)
            except KeyError:
                pass
            else:
                raise RuntimeError("preexisting KedgeFlow group")
        with tempfile.TemporaryDirectory(prefix="kf-systemd-smoke-") as temporary:
            private = Path(temporary)
            snapshot = private / "bundle.tar.gz"
            pack = runpy.run_path(str(ROOT / "scripts/package-linux.py"))
            raw = pack["read_regular"](bundle, 1 << 30)
            if hashlib.sha256(raw).hexdigest() != expected_sha256:
                raise RuntimeError("package checksum mismatch")
            snapshot.write_bytes(raw)
            verified = runpy.run_path(str(ROOT / "scripts/verify-linux-package.py"))["verify"](
                snapshot
            )
            opt = Path("/opt/kedgeflow")
            opt.mkdir(mode=0o755)
            own_opt = True
            release = opt / "releases" / verified["name"]
            release.mkdir(parents=True)
            with tarfile.open(snapshot) as archive:
                for member in archive:
                    relative = Path(*Path(member.name).parts[1:])
                    path = release / relative
                    if member.isdir():
                        path.mkdir(parents=True, exist_ok=True)
                        path.chmod(0o755)
                    else:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise RuntimeError("missing verified payload")
                        path.write_bytes(stream.read())
                        path.chmod(member.mode)
            (opt / "current").symlink_to(release)
            declared = []
            for line in (release / "share/sysusers.d/kedgeflow.conf").read_text().splitlines():
                row = shlex.split(line, comments=True)
                if not row:
                    continue
                if (
                    row[0] != "u"
                    or row[2] != "-"
                    or row[-2:] != ["/nonexistent", "/usr/sbin/nologin"]
                ):
                    raise RuntimeError("unexpected account declaration")
                declared.append(row[1])
            if set(declared) != {"kf-" + role for role in ROLES}:
                raise RuntimeError("unexpected account set")
            # Record intended ownership before provisioning so partial creation is
            # still cleaned up if sysusers exits nonzero.
            report["host_accounts_created"] = True
            created_users.extend(declared)
            run(["systemd-sysusers", release / "share/sysusers.d/kedgeflow.conf"])
            created_users.append("kf-fixture-agent")
            run(
                [
                    "useradd",
                    "--system",
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    "kf-fixture-agent",
                ]
            )
            users = {
                role: (pwd.getpwnam("kf-" + role).pw_uid, pwd.getpwnam("kf-" + role).pw_gid)
                for role in ROLES
            }
            if len({uid for uid, _ in users.values()}) != len(ROLES) or any(
                uid == 0 for uid, _ in users.values()
            ):
                raise RuntimeError("service UIDs are not independently assigned")
            own_config = True
            run(["systemd-tmpfiles", "--create", release / "share/tmpfiles.d/kedgeflow.conf"])
            helper = runpy.run_path(str(ROOT / "scripts/linux-preflight-fixture.py"))
            clients = {}
            configs = helper["generate"](Path("/"), users, monitoring=True, clients=clients)
            for _ in range(2):
                guard = socket.socket()
                guard.bind(("127.0.0.1", 0))
                guards.append(guard)
            origins = [f"https://localhost:{guard.getsockname()[1]}" for guard in guards]

            def local_endpoints(value, witness=False):
                if isinstance(value, dict):
                    for key, item in value.items():
                        if key == "endpoint" and witness:
                            value[key] = origins[1]
                        elif key in ("etcd_endpoint", "etcd_endpoints"):
                            value[key] = [origins[0]] if key == "etcd_endpoints" else origins[0]
                        elif key in (
                            "query_url",
                            "collector_url",
                            "target_url",
                            "broker_endpoint",
                            "control_url",
                        ):
                            value[key] = origins[0] + "/" + key
                        elif isinstance(item, (dict, list)):
                            local_endpoints(item, key == "restore_gate")
                elif isinstance(value, list):
                    for item in value:
                        local_endpoints(item, witness)

            for role, (path, config) in configs.items():
                incoming_query = config.get("query_url") if role == "sql-target" else None
                local_endpoints(config)
                if incoming_query is not None:
                    config["query_url"] = incoming_query
                if "operations_dependencies" in config:
                    for dependency in config["operations_dependencies"].values():
                        dependency["url"] = origins[0] + "/ops/ready"
                if role == "supervisor":
                    config["recovery"]["operations"]["collector"]["url"] = origins[0] + "/ops/ready"
                if role == "sql-target":
                    config["database"]["socket_directory"] = str(private / "absent-database")
                path.write_text(json.dumps(config))
            (Path("/etc/kedgeflow/sql-target/service.env")).write_text(
                "KF_POSTGRES_PEER_UID=64001\n"
            )
            outside = Path("/tmp") / (private.name + "-outside")
            outside.write_bytes(b"synthetic outside canary")
            outside.chmod(0o644)
            probe = opt / "fixture/sandbox-probe.py"
            probe.parent.mkdir()
            probe.write_text(PROBE)
            probe.chmod(0o644)
            monitor_script = probe.parent / "monitor-request.py"
            monitor_script.write_text(MONITOR_REQUEST)
            monitor_script.chmod(0o644)
            agent = pwd.getpwnam("kf-fixture-agent")
            client_paths = {}
            for identity, material in clients.items():
                directory = (
                    private / "monitor-client" if identity == "monitor" else probe.parent / "agent"
                )
                directory.mkdir(mode=0o700)
                for name, raw in material.items():
                    path = directory / name
                    path.write_bytes(raw)
                    path.chmod(0o400)
                    if identity == "agent":
                        os.chown(path, agent.pw_uid, agent.pw_gid)
                if identity == "agent":
                    os.chown(directory, agent.pw_uid, agent.pw_gid)
                client_paths[identity] = directory

            def monitor_url(role):
                config = configs["supervisor" if role == "recovery" else role][1]
                if role == "recovery":
                    return config["recovery"]["operations"]["external_url"]
                application = config.get(
                    "external_url", config.get("admission_url", config.get("dispatch_url"))
                )
                parsed = urlsplit(application)
                return f"{parsed.scheme}://{parsed.netloc}/ops/ready"

            def observe_monitor(role, identity="monitor"):
                directory = client_paths[identity]
                argv = [
                    "/usr/bin/python3",
                    monitor_script,
                    monitor_url(role),
                    directory / "ca",
                    directory / "certificate",
                    directory / "private_key",
                ]
                if identity == "agent":
                    argv = [
                        "setpriv",
                        f"--reuid={agent.pw_uid}",
                        f"--regid={agent.pw_gid}",
                        "--clear-groups",
                        "--no-new-privs",
                        *argv,
                    ]
                deadline = time.monotonic() + 8
                while True:
                    result = run(argv, check=False, timeout=12)
                    if result.returncode == 0:
                        break
                    if (
                        "ConnectionRefusedError" not in result.stderr
                        or time.monotonic() >= deadline
                    ):
                        raise RuntimeError("monitor request failed: " + result.stderr[-1500:])
                    time.sleep(0.05)
                value = json.loads(result.stdout)
                if identity == "monitor":
                    body = value["report"]
                    assert value["status"] == 503 and value["cache_control"] == "no-store"
                    assert body["profile"] == "KF-SERVICE-READINESS-0.1-draft"
                    assert body["role"] == ("supervision" if role == "recovery" else role)
                    assert body["ready"] is False and body["execution_authority"] is False
                else:
                    assert value["status"] == 403
                return value

            binaries = {
                "gateway": "kf-proxy",
                "control": "kf-control",
                "broker": "kf-broker",
                "sql-target": "kf-postgres-target",
                "recovery": "kf-recover",
                "supervisor": "kf-supervise",
                "collector": "kf-outcomes",
                "governance": "kf-governance",
                "operator": "kf-restore",
            }
            for role, (path, _) in configs.items():
                uid, gid = users["recovery" if role == "supervisor" else role]
                args = [
                    release / "bin" / binaries[role],
                    "--config",
                    path,
                    "--custody-root",
                    path.parent,
                    "--require-managed",
                    "--check",
                ]
                if role == "sql-target":
                    args += ["--postgres-peer-uid", "64001"]
                if role in (
                    "gateway",
                    "control",
                    "broker",
                    "sql-target",
                    "collector",
                    "governance",
                ):
                    args += [
                        "--operations-url",
                        monitor_url(role),
                        "--operations-workload",
                        helper["MONITOR_WORKLOAD"],
                    ]
                run(
                    [
                        "setpriv",
                        f"--reuid={uid}",
                        f"--regid={gid}",
                        "--clear-groups",
                        "--no-new-privs",
                        *args,
                    ]
                )
                observations.append(
                    {"role": role, "event": "material_preflight_passed", "uid": uid}
                )

            for source in (release / "share/systemd").iterdir():
                target = Path("/etc/systemd/system") / source.name
                shutil.copyfile(source, target)
                installed_units.append(source.name)
            for role in LIVE:
                canary = Path("/etc/kedgeflow") / role / "sandbox-canary"
                canary.write_bytes(b"synthetic")
                canary.chmod(0o600)
                os.chown(canary, *users[role])
                uid, gid = users[role]
                run(
                    [
                        "setpriv",
                        f"--reuid={uid}",
                        f"--regid={gid}",
                        "--clear-groups",
                        "/usr/bin/python3",
                        "-c",
                        "import sys; open(sys.argv[1],'ab').write(b'x')",
                        canary,
                    ]
                )
                dropin = Path("/etc/systemd/system") / f"kedgeflow-{role}.service.d"
                dropin.mkdir()
                overrides = (
                    f"[Service]\nExecStartPost=/usr/bin/python3 {probe} {canary} {outside}\n"
                )
                if role != "recovery":
                    unit = (
                        (release / "share/systemd" / f"kedgeflow-{role}.service")
                        .read_text()
                        .splitlines()
                    )
                    for directive in ("ExecStartPre", "ExecStart"):
                        original = next(
                            line.split("=", 1)[1]
                            for line in unit
                            if line.startswith(directive + "=")
                        )
                        args = [
                            *shlex.split(original),
                            "--operations-url",
                            monitor_url(role),
                            "--operations-workload",
                            helper["MONITOR_WORKLOAD"],
                        ]
                        overrides += f"{directive}=\n{directive}={shlex.join(args)}\n"
                (dropin / "fixture-probe.conf").write_text(overrides)
            run(["systemctl", "daemon-reload"])
            report["runtime_units_started"] = True
            run(["systemctl", "start", "--no-block", "kedgeflow.target"])
            for role in LIVE:
                unit = f"kedgeflow-{role}.service"
                value = await_state(unit, "active")
                run(["systemctl", "cat", "--no-pager", unit])
                pid = int(value["MainPID"])
                until = time.monotonic() + 10
                while time.monotonic() < until:
                    status = dict(
                        line.split(":", 1)
                        for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                        if ":" in line
                    )
                    if int(status["SigCgt"].strip(), 16) & (1 << (signal.SIGTERM - 1)):
                        break
                    time.sleep(0.05)
                else:
                    raise RuntimeError("application SIGTERM handler not installed")
                assert int(status["Uid"].split()[1]) == users[role][0]
                assert (
                    int(status["CapEff"].strip(), 16) == 0
                    and status["NoNewPrivs"].strip() == "1"
                    and status["Seccomp"].strip() == "2"
                )
                observations.append(
                    {
                        "role": role,
                        "event": "started",
                        "pid": pid,
                        "uid": users[role][0],
                        "capabilities": 0,
                        "no_new_privileges": True,
                        "seccomp_filter": True,
                    }
                )
                logs = run(
                    [
                        "journalctl",
                        "--no-pager",
                        "-u",
                        unit,
                        "-o",
                        "cat",
                        "_SYSTEMD_INVOCATION_ID=" + value["InvocationID"],
                    ]
                ).stdout
                assert "KEDGEFLOW_SANDBOX_PROBE " in logs
                observations.append(
                    {
                        "role": role,
                        "event": "sandbox_probe",
                        "records": [
                            json.loads(line.split("KEDGEFLOW_SANDBOX_PROBE ", 1)[1])
                            for line in logs.splitlines()
                            if "KEDGEFLOW_SANDBOX_PROBE " in line
                        ],
                    }
                )
                if role in ("control", "broker"):
                    observations.append(
                        {"role": role, "event": "listener_without_authority_is_not_readiness"}
                    )
                if role in LIVE:
                    config = configs["supervisor" if role == "recovery" else role][1]
                    material = (
                        config["recovery"]["operations"]
                        if role == "recovery"
                        else config["control"]
                        if role == "governance"
                        else config
                    )
                    context = ssl.create_default_context(cafile=material["workload_ca"])
                    endpoint = urlsplit(monitor_url(role))
                    host, port = endpoint.hostname, endpoint.port
                    # No certificate must never produce an HTTP success. Wait for
                    # the real listener, rather than treating Type=exec as readiness.
                    until = time.monotonic() + 8
                    while True:
                        try:
                            with socket.create_connection((host, int(port)), timeout=2) as sock:
                                with context.wrap_socket(
                                    sock, server_hostname="localhost"
                                ) as stream:
                                    stream.sendall(
                                        b"GET / HTTP/1.1\r\nHost: localhost\r\n"
                                        b"Connection: close\r\n\r\n"
                                    )
                                    reply = stream.recv(1024)
                                    assert not reply, "unauthenticated HTTP response"
                            break
                        except ssl.SSLCertVerificationError:
                            raise
                        except (ssl.SSLError, ConnectionResetError):
                            break
                        except ConnectionRefusedError:
                            if time.monotonic() > until:
                                raise
                            time.sleep(0.05)
                    observations.append({"role": role, "event": "no_client_certificate_refused"})
                value = observe_monitor(role)
                observations.append(
                    {"role": role, "event": "typed_unready_monitor", "observation": value}
                )
                observe_monitor(role, "agent")
                observations.append(
                    {"role": role, "event": "agent_monitor_denied", "uid": agent.pw_uid}
                )
                run(["systemctl", "restart", unit])
                restarted = await_state(unit, "active")
                assert int(restarted["MainPID"]) != pid
                observations.append(
                    {"role": role, "event": "restarted", "pid": int(restarted["MainPID"])}
                )
                observe_monitor(role)
                observations.append({"role": role, "event": "monitor_unready_after_restart"})
            for role in FAILED:
                value = await_state(f"kedgeflow-{role}.service", "failed", deadline=40)
                observations.append(
                    {
                        "role": role,
                        "event": "unavailable_authority_refused",
                        "result": value["Result"],
                    }
                )
            operator = run(["systemctl", "start", "kedgeflow-restore-status.service"], check=False)
            assert operator.returncode != 0, "restore status fabricated unavailable authority"
            agent = pwd.getpwnam("kf-fixture-agent")
            for role, (path, config) in configs.items():
                if role == "supervisor":
                    continue
                value = run(
                    [
                        "setpriv",
                        f"--reuid={agent.pw_uid}",
                        f"--regid={agent.pw_gid}",
                        "--clear-groups",
                        "--no-new-privs",
                        "/usr/bin/python3",
                        "-c",
                        "import sys; open(sys.argv[1],'rb').read(1)",
                        path,
                    ],
                    check=False,
                )
                assert value.returncode != 0
                observations.append({"role": role, "event": "agent_configuration_read_denied"})
            run(["systemctl", "stop", "kedgeflow.target"])
            for role in LIVE:
                value = await_state(f"kedgeflow-{role}.service", "inactive")
                assert value["ExecMainStatus"] == "0" and value["Result"] == "success", value
                observations.append({"role": role, "event": "stopped_normally", "status": 0})
            outside.unlink()
            assert all(
                hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
                for name, digest in source_hashes.items()
            )
            report.update(
                status="passed_installed_systemd_smoke",
                bundle=verified["name"],
                bundle_sha256=expected_sha256,
                users=users,
                systemd=run(["systemd-analyze", "--version"]).stdout.splitlines()[0],
                source_sha256=source_hashes,
            )
    finally:
        cleanup = []
        for unit in reversed(installed_units):
            run(["systemctl", "stop", unit], check=False, timeout=45)
            run(["systemctl", "reset-failed", unit], check=False)
            path = Path("/etc/systemd/system") / unit
            if path.exists():
                path.unlink()
            dropin = path.with_name(path.name + ".d")
            if dropin.exists():
                shutil.rmtree(dropin)
        if installed_units:
            run(["systemctl", "daemon-reload"], check=False)
        for name in reversed(created_users):
            try:
                pwd.getpwnam(name)
            except KeyError:
                pass
            else:
                removed = run(["userdel", name], check=False)
                if removed.returncode:
                    cleanup.append("account removal failed: " + name)
            group = run(["getent", "group", name], check=False)
            if group.returncode == 0:
                run(["groupdel", name], check=False)
        if own_config:
            shutil.rmtree("/etc/kedgeflow")
        if own_opt:
            shutil.rmtree("/opt/kedgeflow")
        for guard in guards:
            guard.close()
        if "outside" in locals() and outside.exists():
            outside.unlink()
        for name in created_users:
            try:
                pwd.getpwnam(name)
            except KeyError:
                pass
            else:
                cleanup.append("account retained: " + name)
            try:
                grp.getgrnam(name)
            except KeyError:
                pass
            else:
                cleanup.append("group retained: " + name)
        report["cleanup_errors"] = cleanup
        report["installed_paths_removed"] = (
            not Path("/opt/kedgeflow").exists() and not Path("/etc/kedgeflow").exists()
        )
        if cleanup:
            report["status"] = "failed_cleanup"
        print(json.dumps(report, indent=2))
        if cleanup:
            raise RuntimeError("systemd fixture cleanup incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ephemeral-host", action="store_true")
    parser.add_argument("--accept-test-install", action="store_true")
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    if (
        sys.flags.optimize
        or not args.ephemeral_host
        or not args.accept_test_install
        or platform.system() != "Linux"
        or os.geteuid() != 0
    ):
        parser.error(
            "requires explicit --ephemeral-host --accept-test-install "
            "on a disposable Linux root session"
        )
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        parser.error("requires actual systemd PID 1")
    qualify(args.package, args.sha256)


if __name__ == "__main__":
    main()

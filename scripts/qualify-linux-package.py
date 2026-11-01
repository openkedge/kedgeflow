#!/usr/bin/env python3
"""Qualify staged systemd assets and Linux UID file boundaries, without installing services.

Requires explicit disposable-host opt-in and root on Linux. All account databases,
directories and unit validation stay in a new temporary root. No host account or
service is created. Without --binary-dir, exec-path validation uses /bin/true
placeholders. With binaries, generated local material exercises shipping --check
under distinct kernel UIDs. Neither mode starts the units or their sandboxes.
"""

import argparse
import hashlib
import json
import os
import platform
import pwd
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROLES = ("gateway", "control", "broker", "sql-target", "recovery", "collector", "operator")


def qualify(native_binaries=None):
    commands = []
    source = ROOT / "deploy/linux"
    inputs = [Path(__file__), *(p for p in source.rglob("*") if p.is_file())]
    if native_binaries is not None:
        inputs.extend(
            [
                ROOT / "scripts/linux-preflight-fixture.py",
                *(p for p in (ROOT / "config").rglob("*") if p.is_file()),
            ]
        )
    source_hashes = {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(inputs)
    }

    def run(argv, check=True):
        result = subprocess.run([str(x) for x in argv], capture_output=True, text=True, timeout=30)
        commands.append(
            {
                "argv": [str(x) for x in argv],
                "exit_code": result.returncode,
                "stderr": result.stderr,
            }
        )
        if check and result.returncode:
            raise RuntimeError(f"staged qualification failed: {argv[0]}: {result.stderr}")
        return result

    report = {
        "status": "failed",
        "scope": "staged unit parsing and kernel UID file isolation",
        "runtime_services_started": False,
        "host_accounts_created": False,
    }
    stage = None
    try:
        with tempfile.TemporaryDirectory(prefix="kf-linux-package-") as temporary:
            stage = Path(temporary)
            stage.chmod(0o755)
            etc = stage / "etc"
            etc.mkdir()
            (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
            (etc / "group").write_text("root:x:0:\n")
            lib = stage / "usr/lib"
            for name in ("sysusers.d", "tmpfiles.d", "systemd/system"):
                (lib / name).mkdir(parents=True)
            original = (source / "sysusers.d/kedgeflow.conf").read_text()
            # Keep these synthetic kernel UIDs distinct from the host's accounts.
            (lib / "sysusers.d/kedgeflow.conf").write_text(original + "r - 64000-64999\n")
            shutil.copyfile(source / "tmpfiles.d/kedgeflow.conf", lib / "tmpfiles.d/kedgeflow.conf")
            before = {name: (etc / name).read_bytes() for name in ("passwd", "group")}
            run(["systemd-sysusers", f"--root={stage}", "kedgeflow.conf"])
            users = {}
            for line in (etc / "passwd").read_text().splitlines():
                name, _, uid, gid, _, home, shell = line.split(":")
                if name.startswith("kf-"):
                    assert home == "/nonexistent" and shell == "/usr/sbin/nologin"
                    users[name[3:]] = (int(uid), int(gid))
            assert set(users) == set(ROLES) and len({u[0] for u in users.values()}) == len(ROLES)
            for uid, gid in users.values():
                assert uid > 0 and gid > 0
                try:
                    pwd.getpwuid(uid)
                except KeyError:
                    continue
                raise RuntimeError("staged UID overlaps a host account")
            account_bytes = {name: (etc / name).read_bytes() for name in before}
            run(["systemd-sysusers", f"--root={stage}", "kedgeflow.conf"])
            assert all((etc / name).read_bytes() == raw for name, raw in account_bytes.items())
            run(["systemd-tmpfiles", f"--root={stage}", "--create", "kedgeflow.conf"])
            for role, (uid, gid) in users.items():
                directory = etc / "kedgeflow" / role
                meta = directory.stat()
                assert (
                    meta.st_uid == 0 and meta.st_gid == gid and stat.S_IMODE(meta.st_mode) == 0o750
                )
                material = directory / "synthetic-private-material"
                material.write_bytes(os.urandom(32))
                os.chown(material, uid, gid)
                material.chmod(0o400)
            probes = []

            def probe(uid, gid, role, permitted):
                result = run(
                    [
                        "setpriv",
                        f"--reuid={uid}",
                        f"--regid={gid}",
                        "--clear-groups",
                        "--no-new-privs",
                        "--bounding-set=-all",
                        "--inh-caps=-all",
                        "--ambient-caps=-all",
                        "/usr/bin/python3",
                        "-c",
                        "import sys; open(sys.argv[1], 'rb').read(1)",
                        etc / "kedgeflow" / role / "synthetic-private-material",
                    ],
                    check=False,
                )
                assert (result.returncode == 0) == permitted
                probes.append({"uid": uid, "role": role, "readable": permitted})

            for reader, (uid, gid) in users.items():
                for role in ROLES:
                    probe(uid, gid, role, reader == role)
            agent_uid = 65000
            try:
                pwd.getpwuid(agent_uid)
            except KeyError:
                pass
            else:
                raise RuntimeError("synthetic agent UID overlaps a host account")
            for role in ROLES:
                probe(agent_uid, agent_uid, role, False)
            unit_root = lib / "systemd/system"
            for path in (source / "systemd").iterdir():
                shutil.copyfile(path, unit_root / path.name)
            # Baseline targets and executable placeholders only satisfy path/dependency
            # validation. They are explicitly not executed and do not exercise sandboxes.
            for target in ("sysinit", "basic", "shutdown", "network-online", "multi-user"):
                (unit_root / f"{target}.target").write_text(
                    "[Unit]\nDescription=Staged prerequisite\n"
                )
            binary_dir = stage / "opt/kedgeflow/current/bin"
            binary_dir.mkdir(parents=True)
            for name in ("kf-proxy", "kf-control", "kf-broker", "kf-postgres-target"):
                origin = (
                    native_binaries / name if native_binaries is not None else Path("/bin/true")
                )
                if not origin.is_file() or origin.is_symlink():
                    raise RuntimeError("native preflight requires regular binary files")
                shutil.copyfile(origin, binary_dir / name)
                (binary_dir / name).chmod(0o755)
            units = sorted(p.name for p in (source / "systemd").iterdir())
            verified = run(["systemd-analyze", f"--root={stage}", "--man=no", "verify", *units])
            if verified.stderr.strip():
                raise RuntimeError("unit verification emitted warnings")
            native = []
            if native_binaries is not None:
                helper = runpy.run_path(str(ROOT / "scripts/linux-preflight-fixture.py"))
                configs = helper["generate"](stage, users)
                binaries = {
                    "gateway": "kf-proxy",
                    "control": "kf-control",
                    "broker": "kf-broker",
                    "sql-target": "kf-postgres-target",
                }

                def preflight(role, reader, expected, variant="account"):
                    path, _ = configs[role]
                    uid, gid = users[reader] if reader != "agent" else (agent_uid, agent_uid)
                    args = [
                        "--config",
                        path,
                        "--custody-root",
                        path.parent,
                        "--require-managed",
                        "--check",
                    ]
                    if role == "sql-target":
                        args += ["--postgres-peer-uid", "0" if variant == "zero-peer" else "64001"]
                    result = run(
                        [
                            "setpriv",
                            f"--reuid={uid}",
                            f"--regid={gid}",
                            "--clear-groups",
                            "--no-new-privs",
                            "--bounding-set=-all",
                            "--inh-caps=-all",
                            "--ambient-caps=-all",
                            binary_dir / binaries[role],
                            *args,
                        ],
                        check=False,
                    )
                    assert (result.returncode == 0) == expected, (
                        role,
                        reader,
                        variant,
                        result.stderr,
                    )
                    native.append(
                        {
                            "role": role,
                            "reader": reader,
                            "variant": variant,
                            "accepted": expected,
                            "exit_code": result.returncode,
                        }
                    )

                for role in binaries:
                    for reader in [*ROLES, "agent"]:
                        preflight(role, reader, role == reader)
                    path, config = configs[role]
                    private = Path(config["private_key"])
                    private.chmod(0o644)
                    preflight(role, role, False, "group-readable-key")
                    private.chmod(0o400)
                    renamed = private.with_suffix(".old")
                    private.rename(renamed)
                    private.symlink_to(renamed)
                    preflight(role, role, False, "symlink-key")
                    private.unlink()
                    renamed.rename(private)
                    if role != "sql-target":
                        changed = dict(config)
                        changed[
                            "allow_unmanaged_fixture" if role == "broker" else "require_control"
                        ] = role == "broker"
                        path.write_text(json.dumps(changed))
                        preflight(role, role, False, "unmanaged-config")
                        path.write_text(json.dumps(config))
                    else:
                        preflight(role, role, False, "zero-peer")
            report.update(
                status="passed_staged_linux_package",
                users=users,
                probes=probes,
                units=units,
                sysusers_idempotent=True,
                systemd=run(["systemd-analyze", "--version"]).stdout.splitlines()[0],
                source_sha256=source_hashes,
                native_preflights=native,
                native_database_contacted=False,
                binary_sha256={
                    name: hashlib.sha256((binary_dir / name).read_bytes()).hexdigest()
                    for name in binaries.values()
                }
                if native_binaries is not None
                else {},
            )
            assert all(
                hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
                for name, digest in source_hashes.items()
            )
    finally:
        report["temporary_root_removed"] = stage is not None and not stage.exists()
        report["commands"] = commands
        print(json.dumps(report, indent=2))
    assert report["temporary_root_removed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ephemeral-host", action="store_true")
    parser.add_argument(
        "--binary-dir", type=Path, help="also check shipping binaries under distinct UIDs"
    )
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error("qualification requires Python assertion checks enabled")
    if not args.ephemeral_host or platform.system() != "Linux" or os.geteuid() != 0:
        parser.error("requires --ephemeral-host on a disposable Linux root session")
    qualify(args.binary_dir)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Enroll protected on-host renewal for the seven separated Cura service roles.

The qualified native issuer stays in the unchanged bundle. A separately pinned
Python sink includes split admission/issuer destinations. Passwords and tokens
never leave Services. Requires already authenticated ledgers and host-local PKI.
"""

import argparse
import hashlib
import json
import os
import pwd
import re
import subprocess
from pathlib import Path

DATA = Path("/var/lib/kedgeflow/pilot")
RELEASE = Path("/opt/kedgeflow/current")
ROLES = ("gateway", "admission", "issuer", "broker", "recovery", "governance", "operator")
DOMAINS = {"primary": "ledgera", "witness": "witness"}
PROFILE = "KF-LEDGER-CREDENTIALS-0.1"
PHASE = "preconditions"


def run(argv, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
    if check and result.returncode:
        raise RuntimeError("credential enrollment operation failed")
    return result


def preflight(bundle_id):
    if (
        os.geteuid() != 0
        or not DATA.is_mount()
        or json.loads((DATA / ".host-enrollment.json").read_text())["host"] != "Services"
    ):
        raise RuntimeError("requires privileged retained Services host")
    if not re.fullmatch(r"[a-f0-9]{64}", bundle_id):
        raise ValueError("exact approved bundle ID required")
    manifest = json.loads((RELEASE / "manifest.json").read_text())
    if manifest["bundle_id"] != bundle_id:
        raise RuntimeError("approved native bundle differs")
    return manifest


def bundled(manifest, name):
    path = RELEASE / name
    info = path.lstat()
    expected = manifest["files"][name]
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o7777 != expected["mode"]
        or hashlib.sha256(path.read_bytes()).hexdigest() != expected["sha256"]
    ):
        raise RuntimeError("verified bundle input differs")
    return path


def write_once(path, raw, owner="root", mode=0o400, group=None):
    raw = raw.encode() if isinstance(raw, str) else raw
    user = pwd.getpwnam(owner)
    gid = pwd.getpwnam(group).pw_gid if group is not None else user.pw_gid
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or info.st_nlink != 1
            or info.st_uid != user.pw_uid
            or info.st_gid != gid
            or info.st_mode & 0o7777 != mode
            or path.read_bytes() != raw
        ):
            raise RuntimeError("existing publisher material differs; explicit upgrade required")
        return
    with path.open("xb") as stream:
        stream.write(raw)
    os.chown(path, user.pw_uid, gid)
    path.chmod(mode)


def prepare_account(manifest):
    run(["systemd-sysusers", str(bundled(manifest, "share/ledger-credentials/sysusers.conf"))])
    user = pwd.getpwnam("kf-credentials")
    if (
        not user.pw_uid
        or not user.pw_gid
        or user.pw_shell != "/usr/sbin/nologin"
        or user.pw_dir != "/nonexistent"
        or set(os.getgrouplist(user.pw_name, user.pw_gid)) != {user.pw_gid}
    ):
        raise RuntimeError("publisher account is not isolated")
    return {
        "format": "kedgeflow-cura-publisher-account-v1",
        "uid": user.pw_uid,
        "separate_identity": True,
        "credentials_or_authority_created": False,
    }


def projections(role):
    user = pwd.getpwnam("kf-" + role)
    source = DATA / "configuration" / role / "credentials"
    if not source.exists():
        source.mkdir(mode=0o750)
        os.chown(source, 0, user.pw_gid)
        source.chmod(0o750)
    info = source.lstat()
    if (
        source.is_symlink()
        or not source.is_dir()
        or info.st_uid != 0
        or info.st_gid != user.pw_gid
        or info.st_mode & 0o7777 != 0o750
    ):
        raise RuntimeError("publisher destination directory custody differs")
    target = Path("/etc/kedgeflow") / role / "credentials"
    if (source.stat().st_dev, source.stat().st_ino) != (target.stat().st_dev, target.stat().st_ino):
        raise RuntimeError("credential projection does not bind the retained role directory")
    mounted = run(["findmnt", "--noheadings", "--mountpoint", str(target)], False).returncode == 0
    if not mounted:
        run(["mount", "--bind", str(source), str(target)])
        run(["mount", "-o", "remount,bind,rw", str(target)])
    options = json.loads(run(["findmnt", "--json", "--mountpoint", str(target)]).stdout)[
        "filesystems"
    ][0]["options"]
    if "rw" not in options.split(","):
        raise RuntimeError("credential sink is not a separately writable nested projection")
    row = (
        f"{source} {target} none bind,rw,nofail,"
        f"x-systemd.requires-mounts-for=/etc/kedgeflow/{role} 0 0"
    )
    fstab = Path("/etc/fstab")
    matches = [
        r
        for r in fstab.read_text().splitlines()
        if len(r.split()) > 1 and r.split()[1] == str(target)
    ]
    if matches and matches != [row]:
        raise RuntimeError("credential projection declaration differs")
    if not matches:
        with fstab.open("a") as stream:
            stream.write(row + "\n")


def policies():
    permissions = [
        {"permission": "READWRITE", "key": "/kedgeflow/cura/", "range_end": "/kedgeflow/cura0"}
    ]
    issuer = {
        "profile": PROFILE,
        "staging_root": "/run/kedgeflow/ledger-credentials",
        "issuers": [],
    }
    mapping = {
        "profile": PROFILE,
        "publisher": "kf-credentials",
        "staging_root": issuer["staging_root"],
        "credential_root": "/etc/kedgeflow",
        "destinations": [],
    }
    root = "/etc/kedgeflow/ledger-credentials"
    for role in ROLES:
        for domain, host in DOMAINS.items():
            common = {
                "name": role + "-" + domain,
                "username": "cura-" + role,
                "scope_prefix": "/kedgeflow/cura",
                "permissions": permissions,
            }
            issuer["issuers"].append(
                {
                    **common,
                    "endpoint": "https://" + host + ".cura.kedgeflow.internal:2379",
                    "ca": root + "/ca.pem",
                    "certificate": root + "/identity.pem",
                    "private_key": root + "/identity.key",
                    "password_file": root + "/" + role + "-" + domain + ".password",
                }
            )
            mapping["destinations"].append({**common, "role": role, "filename": domain + ".token"})
    return issuer, mapping


def install_unit(name, base, final):
    path = Path("/etc/systemd/system") / name
    if path.exists() and path.read_text() == base and base != final:
        active = run(["systemctl", "is-active", "--quiet", name], False).returncode == 0
        enabled = run(["systemctl", "is-enabled", "--quiet", name], False).returncode == 0
        if (
            active
            or enabled
            or path.is_symlink()
            or path.stat().st_uid != 0
            or path.stat().st_mode & 0o022
        ):
            raise RuntimeError("refusing upgrade of active or unprotected image-default unit")
        path.unlink()
    write_once(path, final, mode=0o644)


def tokens(mapping):
    values = {}
    for destination in mapping["destinations"]:
        role, filename = destination["role"], destination["filename"]
        user = pwd.getpwnam("kf-" + role)
        path = Path(mapping["credential_root"]) / role / "credentials" / filename
        info = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or info.st_nlink != 1
            or info.st_uid != user.pw_uid
            or info.st_gid != user.pw_gid
            or info.st_mode & 0o7777 != 0o400
        ):
            raise RuntimeError("published token custody differs")
        if run(["runuser", "-u", user.pw_name, "--", "test", "-r", str(path)], False).returncode:
            raise RuntimeError("service cannot read its assigned token")
        for other in ["kf-agent", "kf-credentials", *["kf-" + r for r in ROLES if r != role]]:
            if run(["runuser", "-u", other, "--", "test", "-r", str(path)], False).returncode == 0:
                raise RuntimeError("foreign identity can read service token")
        values[destination["name"]] = path.read_bytes()
    return values


def enroll(manifest, publisher_source, publisher_sha256):
    global PHASE
    prepare_account(manifest)
    native = bundled(manifest, "bin/kf-ledger-credentials")
    raw = publisher_source.read_bytes()
    if (
        not re.fullmatch(r"[a-f0-9]{64}", publisher_sha256)
        or hashlib.sha256(raw).hexdigest() != publisher_sha256
    ):
        raise ValueError("split-role publisher source pin differs")
    root = DATA / "configuration/ledger-credentials"
    target = Path("/etc/kedgeflow/ledger-credentials")
    user = pwd.getpwnam("kf-credentials")
    if (
        not root.is_dir()
        or root.is_symlink()
        or root.stat().st_uid != 0
        or root.stat().st_gid != user.pw_gid
        or root.stat().st_mode & 0o7777 != 0o750
        or (root.stat().st_dev, root.stat().st_ino) != (target.stat().st_dev, target.stat().st_ino)
    ):
        raise RuntimeError("publisher host-local PKI must be enrolled first")
    PHASE = "protected_policies"
    issuer, mapping = policies()
    for role in ROLES:
        projections(role)
        for domain in DOMAINS:
            password = DATA / "operations/ledger-admin" / (domain + "-cura-" + role + ".password")
            info = password.lstat()
            if (
                password.is_symlink()
                or info.st_uid != 0
                or info.st_nlink != 1
                or info.st_mode & 0o7777 != 0o400
            ):
                raise RuntimeError("enrolled password custody differs")
            write_once(
                root / (role + "-" + domain + ".password"), password.read_bytes(), "kf-credentials"
            )
    write_once(
        root / "issuer.json",
        json.dumps(issuer, indent=2) + "\n",
        mode=0o440,
        group="kf-credentials",
    )
    write_once(root / "mapping.json", json.dumps(mapping, indent=2) + "\n")
    write_once(
        root / "resolv.conf", "nameserver 10.87.0.2\noptions timeout:2 attempts:2\n", mode=0o444
    )
    overlay = Path("/usr/local/libexec") / (
        "kf-cura-ledger-publish-" + publisher_sha256[:16] + ".py"
    )
    overlay.parent.mkdir(mode=0o755, exist_ok=True)
    if (
        overlay.parent.is_symlink()
        or overlay.parent.stat().st_uid != 0
        or overlay.parent.stat().st_mode & 0o022
    ):
        raise RuntimeError("unprotected publisher executable ancestor")
    overlay.parent.chmod(0o755)
    write_once(overlay, raw, mode=0o755)
    tmpfiles = (
        "d /run/kedgeflow 0755 root root -\n"
        "d /run/kedgeflow/ledger-credentials 0750 kf-credentials kf-credentials -\n"
    )
    tmpfile = Path("/etc/tmpfiles.d/kedgeflow-cura-ledger-credentials.conf")
    write_once(tmpfile, tmpfiles, mode=0o644)
    run(["systemd-tmpfiles", "--create", str(tmpfile)])
    for kind in ["issue", "publish"]:
        name = "kedgeflow-ledger-" + kind + ".service"
        base = bundled(manifest, "share/ledger-credentials/" + name).read_text()
        final = base + f"\n[Unit]\nRequiresMountsFor={DATA} {target}\n[Service]\n"
        if kind == "issue":
            final += (
                f"BindReadOnlyPaths={target}/resolv.conf:/etc/resolv.conf\n"
                "IPAddressDeny=any\nIPAddressAllow=10.87.0.0/16\n"
            )
        else:
            final += (
                "ExecStart=\nExecStart=/usr/bin/python3 "
                + str(overlay)
                + " --config "
                + str(target / "mapping.json")
                + "\nReadWritePaths=\nReadWritePaths="
                + " ".join("/etc/kedgeflow/" + role + "/credentials" for role in ROLES)
                + "\n"
            )
        install_unit(name, base, final)
    timer = "kedgeflow-ledger-publish.timer"
    base = bundled(manifest, "share/ledger-credentials/" + timer).read_text()
    install_unit(timer, base, base)
    run(["systemctl", "daemon-reload"])
    PHASE = "native_issuer_preflight"
    run(
        [
            "runuser",
            "-u",
            "kf-credentials",
            "--",
            str(native),
            "--config",
            str(target / "issuer.json"),
            "--custody-root",
            str(target),
            "--check",
        ]
    )
    PHASE = "two_actual_publications"
    run(["systemctl", "start", "kedgeflow-ledger-publish.service"])
    before = tokens(mapping)
    run(["systemctl", "start", "kedgeflow-ledger-publish.service"])
    after = tokens(mapping)
    if set(before) != set(after) or any(before[name] == after[name] for name in before):
        raise RuntimeError("fresh native authentication did not replace every service token")
    PHASE = "renewal_timer"
    run(["systemctl", "enable", "--now", timer])
    run(["systemctl", "is-active", "--quiet", timer])
    return {
        "format": "kedgeflow-cura-credential-publication-v1",
        "status": "two_actual_publications_passed",
        "publisher_uid": user.pw_uid,
        "service_roles": list(ROLES),
        "token_files": len(after),
        "all_tokens_replaced": True,
        "owner_only_service_files": True,
        "agent_publisher_and_foreign_service_reads_refused": True,
        "native_issuer_bundle_id": manifest["bundle_id"],
        "sink_overlay_sha256": publisher_sha256,
        "native_bundle_files_modified": False,
        "renewal_timer_enabled": True,
        "expiry_and_outage_qualification": "PENDING",
        "tokens_or_passwords_returned": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--prepare-account", action="store_true")
    parser.add_argument("--publisher-source", type=Path)
    parser.add_argument("--publisher-sha256")
    parser.add_argument("--operator-bootstrap", action="store_true")
    args = parser.parse_args()
    if not args.operator_bootstrap:
        parser.error("explicit operator bootstrap required")
    try:
        manifest = preflight(args.bundle_id)
        result = (
            prepare_account(manifest)
            if args.prepare_account
            else enroll(manifest, args.publisher_source, args.publisher_sha256)
        )
        print(json.dumps(result, indent=2))
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None

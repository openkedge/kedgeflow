#!/usr/bin/env python3
"""Take an on-host cold baseline copy before the first native SQL dispatch.

Uses only the enrolled Sql volume. No restore, database initialization, credential
export, authority reset, independent custody or enterprise acceptance is performed.
"""

import argparse
import hashlib
import json
import os
import pwd
import runpy
import shutil
import stat
import subprocess
import time
from pathlib import Path

DATA = Path("/var/lib/kedgeflow/pilot")
BASE = Path("/usr/local/sbin/kf-enroll-cura-postgres.py")
BASE_SHA256 = "3d2efac92adfe64fac808479d814341a78cb91569685380590fb97eecede3eae"
DEADLINE = 1795420800
PHASE = "retained_sql_preconditions"


def run(argv, accepted=True, timeout=60):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if accepted and result.returncode:
        raise RuntimeError("fixed cold backup operation refused")
    return result


def inventory(root):
    """Refuse links, special files and unexpectedly large copies before opening data."""
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("cold backup root must be an actual directory")
    files = {}
    total = 0
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError("cold backup forbids links and special files")
        total += info.st_size
        if total > 4 << 30 or len(files) >= 100_000:
            raise RuntimeError("cold backup inventory exceeds bounded pilot copy")
        files[str(path.relative_to(root))] = {"size": info.st_size, "mode": info.st_mode & 0o7777}
    return files, total


def digests(root, files):
    result = {}
    for relative, expected in files.items():
        path = root / relative
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size != expected["size"]
            ):
                raise RuntimeError("cold backup inventory changed while reading")
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        result[relative] = {**expected, "sha256": digest}
    return result


def private_directory(path):
    if not path.exists():
        path.mkdir(mode=0o700)
    info = path.lstat()
    if path.is_symlink() or not path.is_dir() or info.st_uid != 0 or info.st_mode & 0o7777 != 0o700:
        raise RuntimeError("cold backup custody directory differs")


def backup():
    global PHASE
    if (
        os.geteuid() != 0
        or not DATA.is_mount()
        or json.loads((DATA / ".host-enrollment.json").read_text())["host"] != "Sql"
        or time.time() >= DEADLINE
        or BASE.is_symlink()
        or BASE.stat().st_uid != 0
        or BASE.stat().st_mode & 0o022
        or hashlib.sha256(BASE.read_bytes()).hexdigest() != BASE_SHA256
    ):
        raise RuntimeError("exact enrolled Sql host and approved window required")
    base = runpy.run_path(str(BASE))
    owner = pwd.getpwnam("kf-postgres")
    pgdata = DATA / "postgresql"
    if (
        pgdata.is_symlink()
        or pgdata.stat().st_uid != owner.pw_uid
        or (pgdata / "PG_VERSION").read_text().strip() != "18"
        or run(
            ["systemctl", "is-active", "--quiet", "kedgeflow-postgres.service"], False
        ).returncode
        or run(
            ["systemctl", "is-active", "--quiet", "kedgeflow-postgres-target.service"], False
        ).returncode
        == 0
        or run(
            ["systemctl", "is-active", "--quiet", "kedgeflow-sql-target.service"], False
        ).returncode
        == 0
    ):
        raise RuntimeError("requires running enrolled PostgreSQL before target activation")
    before = json.loads(base["snapshot"]())
    resources, attempts = before["resources"], before["attempts"] or []
    if (
        len(resources) != 1
        or attempts
        or any(
            resources[0][k] != v
            for k, v in {
                "tenant": "cura-pilot",
                "resource_id": "slot-a",
                "version": 1,
                "last_fence": 0,
                "incarnation": "cura-reservation-d7081c35b89a41a88b59a029fddc8f5d",
            }.items()
        )
    ):
        raise RuntimeError("pre-first-dispatch baseline differs; never reset")
    private_directory(DATA / "backups")
    private_directory(DATA / "backups/sql")
    final = DATA / "backups/sql/pre-first-dispatch-20261122"
    staging = DATA / "backups/sql/pre-first-dispatch-20261122.incomplete"
    if final.exists() or staging.exists():
        raise RuntimeError(
            "backup or interrupted attempt exists; never overwrite or replay automatically"
        )
    if shutil.disk_usage(DATA).free < 8 << 30:
        raise RuntimeError("insufficient retained volume space for bounded baseline copy")
    private_directory(staging)
    observer_running = (
        run(
            ["systemctl", "is-active", "--quiet", "kedgeflow-sql-observer.service"], False
        ).returncode
        == 0
    )
    started = time.monotonic()
    failed_phase = None
    PHASE = "quiesce_observer_and_database"
    try:
        if observer_running:
            run(["systemctl", "stop", "kedgeflow-sql-observer.service"])
        run(["systemctl", "stop", "kedgeflow-postgres.service"])
        if (pgdata / "postmaster.pid").exists():
            raise RuntimeError("PostgreSQL did not complete cold shutdown")
        control = run(
            [
                "runuser",
                "-u",
                "kf-postgres",
                "--",
                "/opt/kedgeflow/runtime/postgres/bin/pg_controldata",
                str(pgdata),
            ]
        ).stdout
        fields = dict(line.split(":", 1) for line in control.splitlines() if ":" in line)
        if fields.get("Database cluster state", "").strip() != "shut down":
            raise RuntimeError("cold copy requires clean PostgreSQL shutdown")
        PHASE = "bounded_physical_copy"
        files, size = inventory(pgdata)
        original = digests(pgdata, files)
        shutil.copytree(pgdata, staging / "data", symlinks=False)
        copied = digests(staging / "data", files)
        if original != copied or inventory(staging / "data")[0] != files:
            raise RuntimeError("physical backup integrity differs")
        for relative in files:
            with (staging / "data" / relative).open("rb") as stream:
                os.fsync(stream.fileno())
        manifest = {
            "profile": "kedgeflow-cura-sql-cold-baseline-v1",
            "files": copied,
            "database_system_identifier": fields["Database system identifier"].strip(),
            "checkpoint_lsn": fields["Latest checkpoint location"].strip(),
            "postgres_version": "18.3",
            "resource_and_attempt_snapshot": before,
            "independent_storage_custody": "BLOCKED_EXTERNAL_INPUT",
        }
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        with (staging / "manifest.json").open("xb") as stream:
            os.chmod(stream.name, 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        for directory in sorted(
            [p for p in staging.rglob("*") if p.is_dir()] + [staging],
            key=lambda p: len(p.parts),
            reverse=True,
        ):
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        staging.rename(final)
        directory_fd = os.open(final.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        failed_phase = PHASE
        raise
    finally:
        PHASE = "resume_original_database_and_observer"
        run(["systemctl", "start", "kedgeflow-postgres.service"])
        ready = False
        for _ in range(30):
            try:
                ready = json.loads(base["snapshot"]()) == before
                break
            except RuntimeError:
                time.sleep(1)
        if not ready:
            raise RuntimeError("original database did not resume with retained baseline")
        if observer_running:
            run(["systemctl", "start", "kedgeflow-sql-observer.service"])
        if failed_phase:
            PHASE = failed_phase
    if json.loads(base["snapshot"]()) != before:
        raise RuntimeError("original database state differs after cold backup")
    return {
        "profile": "kedgeflow-cura-sql-cold-baseline-observation-v1",
        "status": "physical_baseline_copy_verified",
        "files": len(files),
        "bytes": size,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "version": 1,
        "fence": 0,
        "attempt_rows": 0,
        "original_database_resumed": True,
        "observer_resumed": observer_running,
        "quiesced_seconds": round(time.monotonic() - started, 3),
        "backup_data_exported": False,
        "restore_performed": False,
        "authority_or_history_reset": False,
        "independent_storage_custody": "BLOCKED_EXTERNAL_INPUT",
        "enterprise_qualified": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before-first-dispatch", action="store_true", required=True)
    parser.parse_args()
    try:
        print(json.dumps(backup()))
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None

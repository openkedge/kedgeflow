#!/usr/bin/env python3
"""Install a fresh audited batch using a root-owned, closed destination mapping.

No network, authentication, role administration, or daemon restart is performed.
Each destination replacement is atomic; a batch is not a multi-file transaction.
"""

import argparse
import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import sys
import time
from contextlib import ExitStack
from pathlib import PurePosixPath

PROFILE = "KF-LEDGER-CREDENTIALS-0.1"
ROLES = {"gateway", "control", "broker", "recovery", "collector", "operator", "governance"}
NAME = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


def require(condition):
    if not condition:
        raise ValueError("credential publication refused")


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def invalid_number(_):
    raise ValueError("invalid number")


def decode(raw):
    return json.loads(
        raw, object_pairs_hook=unique, parse_constant=invalid_number, parse_float=invalid_number
    )


def fields(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected.split()))


def absolute(path):
    require(isinstance(path, str))
    parts = PurePosixPath(path).parts
    require(
        path.startswith("/")
        and str(PurePosixPath(path)) == path
        and len(parts) > 1
        and ".." not in parts
    )
    return parts[1:]


def directory(stack, path, final_uid=0, final_gid=None, final_mode=None):
    parts = absolute(path)
    # Directory descriptors cannot be wrapped with fdopen on all supported Pythons.
    fd = os.open("/", FLAGS | os.O_DIRECTORY)
    stack.callback(os.close, fd)
    for index, part in enumerate(parts):
        parent = os.fstat(fd)
        sticky = parent.st_uid == 0 and parent.st_mode & stat.S_ISVTX
        require(
            parent.st_uid == 0
            and not parent.st_mode & 0o6000
            and (not parent.st_mode & 0o022 or sticky)
        )
        fd = os.open(part, FLAGS | os.O_DIRECTORY, dir_fd=fd)
        stack.callback(os.close, fd)
        if index + 1 < len(parts):
            require(os.fstat(fd).st_uid == 0)
    meta = os.fstat(fd)
    require(meta.st_uid == final_uid and not meta.st_mode & 0o7022)
    if final_gid is not None:
        require(meta.st_gid == final_gid)
    if final_mode is not None:
        require(stat.S_IMODE(meta.st_mode) == final_mode)
    return fd


def read_file(fd, filename, uid, gid, mode, bound):
    opened = os.open(filename, FLAGS, dir_fd=fd)
    with os.fdopen(opened, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_uid == uid
            and (gid is None or before.st_gid == gid)
            and stat.S_IMODE(before.st_mode) == mode
            and before.st_size <= bound
        )
        raw = stream.read(bound + 1)
        after = os.fstat(stream.fileno())
        stable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        require(len(raw) <= bound and all(getattr(before, k) == getattr(after, k) for k in stable))
    return raw


def permissions_digest(permissions, scope):
    require(
        isinstance(permissions, list)
        and 1 <= len(permissions) <= 128
        and isinstance(scope, str)
        and scope.startswith("/")
        and len(scope) <= 512
        and all(NAME.fullmatch(p) and p not in (".", "..") for p in scope.split("/")[1:])
    )
    ranges = set()
    for p in permissions:
        fields(p, "permission key range_end")
        require(
            p["permission"] in ("READ", "WRITE", "READWRITE")
            and isinstance(p["key"], str)
            and p["key"].startswith(scope + "/")
            and "\0" not in p["key"]
            and isinstance(p["range_end"], str)
            and (not p["range_end"] or p["key"] < p["range_end"] <= scope + "0")
        )
        pair = (p["key"], p["range_end"])
        require(pair not in ranges)
        ranges.add(pair)
    ordered = sorted(permissions, key=lambda p: (p["permission"], p["key"], p["range_end"]))
    raw = json.dumps(ordered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    domain = b"KedgeFlow/KF-JSON-0.2/ledger-credential-permissions\0"
    return hashlib.sha256(domain + raw).hexdigest()


def account(name):
    require(isinstance(name, str) and NAME.fullmatch(name))
    entry = pwd.getpwnam(name)
    require(entry.pw_uid != 0 and entry.pw_gid != 0)
    return entry.pw_uid, entry.pw_gid


def plan(stack, config, batch):
    fields(batch, "profile created_at credentials")
    require(
        batch["profile"] == PROFILE
        and type(batch["created_at"]) is int
        and -1000 <= int(time.time() * 1000) - batch["created_at"] <= 10000
        and isinstance(batch["credentials"], list)
        and len(batch["credentials"]) == len(config["destinations"])
    )
    credentials = {}
    for item in batch["credentials"]:
        fields(item, "name username scope_prefix permissions_digest token")
        require(isinstance(item["name"], str) and item["name"] not in credentials)
        credentials[item["name"]] = item
    plans, targets, names = [], set(), set()
    for destination in config["destinations"]:
        fields(destination, "name username scope_prefix permissions role filename")
        name, role, filename = (destination[k] for k in ("name", "role", "filename"))
        require(
            isinstance(name, str)
            and NAME.fullmatch(name)
            and name not in names
            and role in ROLES
            and isinstance(filename, str)
            and NAME.fullmatch(filename)
            and filename not in (".", "..")
            and (role, filename) not in targets
            and isinstance(destination["username"], str)
            and NAME.fullmatch(destination["username"])
            and destination["username"] != "root"
        )
        names.add(name)
        targets.add((role, filename))
        credential = credentials[name]
        require(all(credential[k] == destination[k] for k in ("name", "username", "scope_prefix")))
        require(
            credential["permissions_digest"]
            == permissions_digest(destination["permissions"], destination["scope_prefix"])
        )
        token = credential["token"]
        require(
            isinstance(token, str)
            and 1 <= len(token) <= 8192
            and all(32 < ord(c) < 127 for c in token)
        )
        uid, gid = account("kf-" + role)
        require(uid != account(config["publisher"])[0])
        fd = directory(
            stack,
            config["credential_root"] + "/" + role + "/credentials",
            final_gid=gid,
            final_mode=0o750,
        )
        try:
            # Refuse unsafe existing targets before creating any replacement.
            existing = os.stat(filename, dir_fd=fd, follow_symlinks=False)
            require(
                stat.S_ISREG(existing.st_mode)
                and existing.st_nlink == 1
                and existing.st_uid == uid
                and existing.st_gid == gid
                and stat.S_IMODE(existing.st_mode) == 0o400
                and existing.st_size <= 8192
            )
        except FileNotFoundError:
            pass
        plans.append((fd, filename, uid, gid, token.encode("ascii")))
    require(names == set(credentials))
    return plans


def publish(config_path):
    require(os.geteuid() == 0)
    with ExitStack() as stack:
        parts = absolute(config_path)
        parent = directory(stack, "/" + "/".join(parts[:-1]))
        config = decode(read_file(parent, parts[-1], 0, None, 0o400, 1 << 20))
        fields(config, "profile publisher staging_root credential_root destinations")
        require(
            config["profile"] == PROFILE
            and isinstance(config["destinations"], list)
            and 1 <= len(config["destinations"]) <= 16
        )
        absolute(config["credential_root"])
        uid, gid = account(config["publisher"])
        stage = directory(stack, config["staging_root"], uid, gid, 0o750)
        batch = decode(read_file(stage, "batch.json", uid, gid, 0o440, 512 << 10))
        plans = plan(stack, config, batch)
        # Prepare/fsync every new file before the first destination is replaced.
        prepared = []
        try:
            for fd, filename, uid, gid, token in plans:
                temporary = ".token-" + secrets.token_hex(16)
                opened = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=fd,
                )
                prepared.append((fd, temporary, filename))
                with os.fdopen(opened, "wb") as stream:
                    stream.write(token)
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o400)
                    os.fchown(stream.fileno(), uid, gid)
                    os.fsync(stream.fileno())
            for fd, temporary, filename in prepared:
                os.rename(temporary, filename, src_dir_fd=fd, dst_dir_fd=fd)
                os.fsync(fd)
        finally:
            for fd, temporary, _ in prepared:
                try:
                    os.unlink(temporary, dir_fd=fd)
                except FileNotFoundError:
                    pass
        return len(plans)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    try:
        count = publish(args.config)
    except Exception:
        # Never print server responses, token bytes, or exception input values.
        print("credential publication refused", file=sys.stderr)
        return 1
    print(f"credential batch installed for {count} configured principals")
    return 0


if __name__ == "__main__":
    sys.exit(main())

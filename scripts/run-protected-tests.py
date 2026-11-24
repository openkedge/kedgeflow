#!/usr/bin/env python3
"""Run fixture tests with private inherited permissions, without weakening custody."""

import os
import stat
import sys

if __name__ == "__main__":
    command = sys.argv[1:]
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("a test command is required")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SystemExit("protected service tests require a non-root fixture identity")
    # Avoid shared, group-writable CI workspace ancestors and macOS /tmp aliases.
    temporary_base = os.path.realpath("/tmp")
    info = os.stat(temporary_base)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)
    ):
        raise SystemExit("a protected canonical system temporary directory is required")
    os.environ["TMPDIR"] = temporary_base
    os.umask(0o077)
    print("protected_fixture_umask=0077", flush=True)
    os.execvp(command[0], command)

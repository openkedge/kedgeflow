#!/usr/bin/env python3
"""Extract fixed categories and source locations, never raw provider logs/credentials."""

import argparse
import json
import re
import runpy
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

MARKERS = {
    "systemd_start_refused": "systemd start refused:",
    "sandbox_not_effective": "shipping unit sandbox not effective",
    "sdk_failed": "official SDK failed:",
    "permission_denied": "Permission denied",
    "executable_failed": "status=203/EXEC",
    "missing_path": "No such file or directory",
    "private_key_read_allowed": "agent read another role's private key",
    "refresh_binding_refused": "identity refresh signature/head/realm/epoch mismatch",
    "expired": "expired",
    "timed_out": "timed out",
    "connection_refused": "Connection refused",
    "assertion_failed": "assertion",
}
ERROR_CLASSES = {
    "AssertionError",
    "FileNotFoundError",
    "PermissionError",
    "RuntimeError",
    "CalledProcessError",
    "TimeoutExpired",
    "JSONDecodeError",
    "KeyError",
}
FILES = {"shipping-sql.log", "systemd-runner.stderr", "systemd-journal.log"}


def categories(raw):
    result = {name: marker in raw for name, marker in MARKERS.items()}
    result["error_classes"] = sorted(
        name for name in ERROR_CLASSES if re.search(r"\b" + name + r"\b", raw)
    )
    result["rust_panic_source_lines"] = sorted(
        {int(line) for line in re.findall(r"tests/support/selfhosted_sql\.rs:(\d+):\d+", raw)}
    )
    result["adapter_source_lines"] = sorted(
        {int(line) for line in re.findall(r'pilot-systemd-role\.py", line (\d+)', raw)}
    )
    result["python_frames"] = [
        {"file": name, "line": int(line)}
        for name, line in re.findall(
            r'File "[^"\n]*/(qualify-systemd-authority\.py|systemd-sql-workflow\.py|'
            r'pilot-systemd-role\.py|subprocess\.py|shutil\.py|pathlib\.py)", line (\d+)', raw
        )
    ]
    result["exit_statuses"] = sorted(
        {int(value) for value in re.findall(r"(?:status=|ExecMainStatus=)([0-9]{1,3})\b", raw)}
    )
    return result


def inspect(run, source, digest):
    downloader = runpy.run_path(str(Path(__file__).with_name("fetch-ci-credential-artifact.py")))
    with tempfile.TemporaryDirectory(prefix="kf-ci-private-inspection-") as temporary:
        archive = downloader["download_artifact"](
            run, source, digest, Path(temporary) / "artifact", "selfhosted-systemd"
        )
        results = {}
        with zipfile.ZipFile(archive) as package:
            for item in package.infolist():
                name = PurePosixPath(item.filename).name
                if name not in FILES:
                    continue
                if name in results or item.file_size > 4 << 20:
                    raise ValueError("bounded unique failure record required")
                results[name] = categories(package.read(item).decode("utf-8", errors="replace"))
        if not results:
            raise ValueError("expected managed failure records absent")
        return {
            "status": "closed_managed_failure_categories",
            "retained_run": run,
            "retained_source": source,
            "categories": results,
            "raw_logs_or_credentials_exported": False,
            "current_source_qualified": False,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=int, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--artifact-sha256", required=True)
    args = parser.parse_args()
    try:
        result = inspect(args.run, args.source, args.artifact_sha256)
        print("::notice title=Managed provider failure categories::" + json.dumps(result))
    except Exception as error:
        print("::error title=Managed failure inspection::" + type(error).__name__)
        raise SystemExit(1) from None

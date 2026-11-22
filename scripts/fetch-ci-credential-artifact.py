#!/usr/bin/env python3
"""Fetch one exact retained CI artifact; never forward its read token to storage.

Only the prior fixture's closed failure category and a verified native executable
are selected. No archive paths are extracted, and no public artifact is CI proof
for the current source. This is a bounded component reproduction aid.
"""

import argparse
import hashlib
import json
import os
import re
import runpy
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

API = "https://api.github.com/repos/openkedge/kedgeflow/actions"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(run_id, source, expected_digest, output):
    if (
        run_id <= 0
        or not re.fullmatch(r"[a-f0-9]{40}", source)
        or not re.fullmatch(r"[a-f0-9]{64}", expected_digest)
    ):
        raise ValueError("exact artifact pins required")
    token = os.environ["KF_CI_ARTIFACT_TOKEN"]
    opener = urllib.request.build_opener(NoRedirect())
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
    }

    def api(path):
        with opener.open(
            urllib.request.Request(API + path, headers=headers), timeout=30
        ) as response:
            raw = response.read((4 << 20) + 1)
            if len(raw) > 4 << 20:
                raise RuntimeError("API metadata bound")
            return json.loads(raw)

    run = api("/runs/" + str(run_id))
    if (
        run["id"] != run_id
        or run["head_sha"] != source
        or run["event"] != "push"
        or run["path"] != ".github/workflows/ci.yml"
        or run["repository"]["full_name"] != "openkedge/kedgeflow"
        or run["head_repository"]["full_name"] != "openkedge/kedgeflow"
        or run["status"] != "completed"
    ):
        raise RuntimeError("retained source/run binding differs")
    page = api("/runs/" + str(run_id) + "/artifacts?per_page=100")
    artifacts = [a for a in page["artifacts"] if a["name"] == "linux-core-runtime"]
    if len(artifacts) != 1 or page["total_count"] != len(page["artifacts"]):
        raise RuntimeError("complete unique artifact metadata required")
    artifact = artifacts[0]
    if (
        artifact["expired"]
        or artifact["digest"] != "sha256:" + expected_digest
        or artifact["workflow_run"]["id"] != run_id
        or artifact["workflow_run"]["head_sha"] != source
    ):
        raise RuntimeError("artifact content/source pin differs")
    try:
        opener.open(
            urllib.request.Request(
                API + "/artifacts/" + str(artifact["id"]) + "/zip", headers=headers
            ),
            timeout=30,
        )
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise RuntimeError("artifact download refused") from None
        download_url = error.headers["Location"]
    else:
        raise RuntimeError("expected signed artifact download redirect")
    if not download_url.startswith("https://"):
        raise RuntimeError("TLS artifact storage required")
    output.mkdir(mode=0o700)
    archive_path = output / "retained-artifact.zip"
    digest, size = hashlib.sha256(), 0
    # A fresh request has no GitHub authorization header or other credentials.
    with (
        urllib.request.urlopen(download_url, timeout=60) as response,
        archive_path.open("xb") as stream,
    ):
        while chunk := response.read(1 << 20):
            size += len(chunk)
            if size > 1 << 30:
                raise RuntimeError("artifact download bound")
            digest.update(chunk)
            stream.write(chunk)
    if digest.hexdigest() != expected_digest:
        raise RuntimeError("downloaded artifact digest differs")
    with zipfile.ZipFile(archive_path) as archive:
        failures = [
            m
            for m in archive.infolist()
            if PurePosixPath(m.filename).name == "linux-ledger-credentials.json"
        ]
        packages = [
            m
            for m in archive.infolist()
            if len(PurePosixPath(m.filename).parts) == 3
            and m.filename.startswith("dist/linux/")
            and m.filename.endswith(".tar.gz")
        ]
        if (
            len(failures) != 1
            or failures[0].file_size > 65536
            or len(packages) != 1
            or packages[0].file_size > 1 << 30
        ):
            raise RuntimeError("retained component inventory differs")
        failure = json.loads(archive.read(failures[0]))
        if (
            set(failure) != {"status", "phase", "error_class"}
            or failure["status"] != "failed"
            or not re.fullmatch(r"[a-z_]{1,80}", failure["phase"])
            or not re.fullmatch(r"[A-Za-z0-9_]{1,80}", failure["error_class"])
        ):
            raise RuntimeError("only a closed prior failure category may be printed")
        print(
            "::notice title=Retained credential failure::"
            + failure["phase"]
            + " ("
            + failure["error_class"]
            + ")",
            flush=True,
        )
        package_path = output / "native-package.tar.gz"
        package_path.write_bytes(archive.read(packages[0]))
    runpy.run_path(str(Path(__file__).with_name("verify-linux-package.py")))["verify"](package_path)
    with tarfile.open(package_path, "r:gz") as archive:
        manifests = [m for m in archive if m.name.endswith("/manifest.json") and m.isfile()]
        if len(manifests) != 1 or manifests[0].size > 1 << 20:
            raise RuntimeError("one bounded verified manifest required")
        manifest = json.loads(archive.extractfile(manifests[0]).read())
        binaries = [
            m for m in archive if m.name.endswith("/bin/kf-ledger-credentials") and m.isfile()
        ]
        if len(binaries) != 1 or binaries[0].size > 128 << 20:
            raise RuntimeError("one bounded credential executable required")
        raw = archive.extractfile(binaries[0]).read()
        binary_directory = output / "bin"
        binary_directory.mkdir(mode=0o755)
        for member in archive:
            relative = PurePosixPath(member.name)
            if len(relative.parts) == 3 and relative.parts[1] == "bin" and member.isfile():
                data = archive.extractfile(member).read()
                expected = manifest["files"]["bin/" + relative.name]["sha256"]
                if hashlib.sha256(data).hexdigest() != expected:
                    raise RuntimeError("native preflight executable pin differs")
                binary_path = binary_directory / relative.name
                binary_path.write_bytes(data)
                binary_path.chmod(0o755)
    if hashlib.sha256(raw).hexdigest() != manifest["files"]["bin/kf-ledger-credentials"]["sha256"]:
        raise RuntimeError("native executable pin differs")
    path = output / "kf-ledger-credentials"
    path.write_bytes(raw)
    path.chmod(0o755)
    return {
        "status": "retained_native_component_verified",
        "retained_source": source,
        "retained_run": run_id,
        "binary_sha256": hashlib.sha256(raw).hexdigest(),
        "current_source_ci_qualified": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=int)
    parser.add_argument("--source", required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(fetch(args.run, args.source, args.artifact_sha256, args.output)))
    except Exception as error:
        print("::error title=Component reproduction artifact::" + type(error).__name__)
        raise SystemExit(1) from None

"""Failure inspection exports fixed categories, never provider text or credentials."""

import hashlib
import io
import json
import runpy
import urllib.error
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_managed_failure_categories_never_return_raw_provider_values():
    module = runpy.run_path(str(ROOT / "scripts/inspect-ci-managed-failure.py"))
    raw = (
        "thread panicked at tests/support/selfhosted_sql.rs:134:4\n"
        "systemd start refused: PRIVATE_PROVIDER_VALUE\n"
        'File "pilot-systemd-role.py", line 166\n'
        "FileNotFoundError: /proc/0/status secret=TOKEN_MUST_NOT_ESCAPE\n"
    )
    report = module["categories"](raw)
    assert report["systemd_start_refused"]
    assert report["rust_panic_source_lines"] == [134]
    assert report["adapter_source_lines"] == [166]
    assert report["error_classes"] == ["FileNotFoundError"]
    assert "PRIVATE_PROVIDER_VALUE" not in json.dumps(report)
    assert "TOKEN_MUST_NOT_ESCAPE" not in json.dumps(report)


def test_artifact_read_token_is_never_forwarded_to_storage(tmp_path, monkeypatch):
    module = runpy.run_path(str(ROOT / "scripts/fetch-ci-credential-artifact.py"))
    raw, source = b"public artifact bytes", "a" * 40
    digest = hashlib.sha256(raw).hexdigest()
    monkeypatch.setenv("KF_CI_ARTIFACT_TOKEN", "test-only-read-token")
    seen = []

    class Opener:
        def open(self, request, timeout):
            seen.append(request)
            if request.full_url.endswith("/zip"):
                raise urllib.error.HTTPError(
                    request.full_url,
                    302,
                    "redirect",
                    {"Location": "https://storage.invalid/signed-public-artifact"},
                    None,
                )
            if "/artifacts?" in request.full_url:
                value = {
                    "total_count": 1,
                    "artifacts": [
                        {
                            "name": "selfhosted-systemd",
                            "id": 2,
                            "expired": False,
                            "digest": "sha256:" + digest,
                            "workflow_run": {"id": 1, "head_sha": source},
                        }
                    ],
                }
            else:
                value = {
                    "id": 1,
                    "head_sha": source,
                    "event": "push",
                    "status": "completed",
                    "path": ".github/workflows/ci.yml",
                    "repository": {"full_name": "openkedge/kedgeflow"},
                    "head_repository": {"full_name": "openkedge/kedgeflow"},
                }
            return io.BytesIO(json.dumps(value).encode())

    monkeypatch.setattr(module["urllib"].request, "build_opener", lambda *args: Opener())

    def storage(request, timeout):
        # Only the URL is passed: no API Request object, header or authorization.
        assert request == "https://storage.invalid/signed-public-artifact"
        return io.BytesIO(raw)

    monkeypatch.setattr(module["urllib"].request, "urlopen", storage)
    result = module["download_artifact"](
        1, source, digest, tmp_path / "download", "selfhosted-systemd"
    )
    assert result.read_bytes() == raw
    assert len(seen) == 3
    assert all(
        request.get_header("Authorization") == "Bearer test-only-read-token" for request in seen
    )

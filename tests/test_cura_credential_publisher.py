"""Split-role credentials stay individually mapped and cannot select admin/Audit secrets."""

import runpy
from pathlib import Path

SCRIPT = runpy.run_path(
    str(Path(__file__).parents[1] / "scripts/enroll-cura-credential-publisher.py")
)


def test_publisher_maps_distinct_control_roles_to_their_own_token_files():
    issuer, mapping = SCRIPT["policies"]()
    assert len(issuer["issuers"]) == len(mapping["destinations"]) == 14
    assert len({d["name"] for d in mapping["destinations"]}) == 14
    assert len({(d["role"], d["filename"]) for d in mapping["destinations"]}) == 14
    for source, destination in zip(issuer["issuers"], mapping["destinations"], strict=True):
        for field in ["name", "username", "scope_prefix", "permissions"]:
            assert source[field] == destination[field]
        assert destination["role"] not in {"control", "collector", "etcd-admin", "root"}
        assert source["username"] == "cura-" + destination["role"]
        assert source["password_file"].endswith("/" + source["name"] + ".password")
        assert source["permissions"] == [
            {"permission": "READWRITE", "key": "/kedgeflow/cura/", "range_end": "/kedgeflow/cura0"}
        ]
    assert {d["role"] for d in mapping["destinations"]} >= {"admission", "issuer"}

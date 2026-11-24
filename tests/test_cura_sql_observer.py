"""Only one registered row can enter the read-only SQL observation contract."""

import copy
import runpy
from pathlib import Path

import pytest

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/enroll-cura-sql-observer.py"))
INCARNATION = "cura-reservation-" + "a" * 32


def test_read_function_is_fixed_to_one_enrolled_row_and_rejects_sql_injection():
    statement = SCRIPT["ddl"](INCARNATION)
    assert "SECURITY DEFINER SET search_path=pg_catalog,pg_temp" in statement
    assert "observe_cura()" in statement and "observe_cura(" + INCARNATION not in statement
    assert "tenant='cura-pilot' AND resource_id='slot-a'" in statement
    assert "REVOKE ALL ON FUNCTION kf_reservation.observe_cura() FROM PUBLIC" in statement
    assert (
        "apply(jsonb)" not in statement and "UPDATE " not in statement and "DROP " not in statement
    )
    for invalid in ["", "x'; DROP SCHEMA kf_reservation CASCADE; --", INCARNATION + "a"]:
        with pytest.raises(ValueError):
            SCRIPT["ddl"](invalid)


def test_observation_refuses_other_resources_unsafe_versions_or_unknown_fields():
    row = {
        "tenant": "cura-pilot",
        "conflict_domain": "cura-sql-pilot:reservations",
        "resource_id": "slot-a",
        "incarnation": INCARNATION,
        "version": "1",
        "last_fence": "0",
        "reservation": "available",
        "active": True,
    }
    assert SCRIPT["observation_check"](row, INCARNATION) == row
    for field, value in [
        ("resource_id", "slot-b"),
        ("tenant", "production"),
        ("incarnation", "older"),
        ("version", "01"),
        ("version", "0"),
        ("version", "9007199254740992"),
        ("version", True),
        ("last_fence", "-1"),
        ("active", "true"),
        ("extra", "value"),
    ]:
        bad = copy.deepcopy(row)
        bad[field] = value
        with pytest.raises(RuntimeError):
            SCRIPT["observation_check"](bad, INCARNATION)

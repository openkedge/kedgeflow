"""Required real-SQL RFC 0048 conditional restore/barrier checks."""

import copy
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor


def qualify_compensation(sql, literal):
    passed = []
    sql("""
        CREATE ROLE kf_inverse_executor NOLOGIN;
        CREATE ROLE kf_inverse_reader NOLOGIN;
        CREATE ROLE kf_inverse_barrier NOLOGIN;
        GRANT USAGE ON SCHEMA kf_compensation
            TO kf_inverse_executor,kf_inverse_reader,kf_inverse_barrier;
        GRANT USAGE ON SCHEMA kf_reservation
            TO kf_inverse_executor,kf_inverse_reader,kf_inverse_barrier;
        GRANT EXECUTE ON FUNCTION kf_compensation.apply(jsonb) TO kf_inverse_executor;
        GRANT EXECUTE ON FUNCTION kf_compensation.lookup(text,text) TO kf_inverse_reader;
        GRANT EXECUTE ON FUNCTION kf_compensation.barrier(text,text,text,text,text)
            TO kf_inverse_barrier;
    """)
    counter = 20000

    def setup(*, forward=True):
        nonlocal counter
        counter += 1
        n = counter
        resource = {"id": f"inverse-{n}", "incarnation": "incarnation-1"}
        state = {"reservation": "original", "resource": resource}
        canonical = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        state_digest = hashlib.sha256(
            b"KedgeFlow/KF-JSON-0.2/postgres-restore-state\0" + canonical
        ).hexdigest()
        capture = dict(
            tenant="inverse",
            conflict_domain="reservations",
            resource=resource,
            baseline_version=1,
            contract_digest=f"{n:064x}",
            restore_state_digest=state_digest,
        )
        sql(
            "INSERT INTO kf_reservation.resource VALUES "
            f"('inverse','reservations','{resource['id']}','incarnation-1',1,0,'original',true);"
        )
        assert json.loads(sql(f"SELECT kf_compensation.capture({literal(capture)});")) == capture
        f = dict(
            profile="KF-POSTGRES-RESERVATION-0.1-draft",
            action="postgres.reservation.set.v1",
            tenant="inverse",
            conflict_domain="reservations",
            attempt_id=f"forward-{n}",
            grant_digest=f"{n + 100000:064x}",
            root_id=f"forward-root-{n}",
            resource=resource,
            expected_version=1,
            fence=1,
            reservation="changed",
            gateway_workload="spiffe://fixture/forward",
            expires_at=int(time.time() * 1000) + 60000,
        )
        if forward:
            assert (
                json.loads(sql(f"SELECT kf_reservation.apply({literal(f)});", "kf_executor"))[
                    "status"
                ]
                == "committed"
            )
        inverse = dict(
            profile="KF-POSTGRES-COMPENSATION-0.1-draft",
            action="kedgeflow.compensation.restore.v1",
            tenant="inverse",
            conflict_domain="reservations",
            attempt_id=f"inverse-{n}",
            grant_digest=f"{n + 200000:064x}",
            root_id=f"inverse-root-{n}",
            resource=resource,
            expected_version=2,
            fence=2,
            gateway_workload="spiffe://fixture/inverse",
            expires_at=int(time.time() * 1000) + 60000,
            contract_digest=capture["contract_digest"],
            forward_root_id=f["root_id"],
            forward_grant_digest=f["grant_digest"],
            forward_attempt_id=f["attempt_id"],
            restore_state_digest=state_digest,
        )
        return capture, f, inverse

    def apply(q, fail=False):
        raw = sql(f"SELECT kf_compensation.apply({literal(q)});", "kf_inverse_executor", fail)
        return None if fail else json.loads(raw)

    def barrier(c, f):
        args = [c["tenant"], c["contract_digest"], f["attempt_id"], f["grant_digest"], f["root_id"]]
        raw = sql(
            "SELECT kf_compensation.barrier(" + ",".join("'" + x + "'" for x in args) + ");",
            "kf_inverse_barrier",
        )
        return json.loads(raw) if raw else None

    c, f, q = setup()
    observed = barrier(c, f)
    assert (
        observed["observed_version"] == 2
        and observed["restore_state_digest"] == c["restore_state_digest"]
    )
    result = apply(q)
    assert result["status"] == "committed" and result["post_version"] == 3
    assert (
        sql(
            "SELECT version||':'||last_fence||':'||reservation FROM kf_reservation.resource "
            f"WHERE tenant='inverse' AND resource_id='{q['resource']['id']}';"
        )
        == "3:2:original"
    )
    assert barrier(c, f) is None
    assert (
        json.loads(
            sql(
                "SELECT kf_compensation.lookup('inverse','" + q["attempt_id"] + "');",
                "kf_inverse_reader",
            )
        )
        == result
    )
    passed.append(
        "inverse: captured restore, exact original barrier, atomic restore and "
        "independent original query"
    )

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert all(v == result for v in pool.map(apply, [q] * 16))
    for k, v in (
        ("attempt_id", "replacement"),
        ("root_id", "replacement"),
        ("grant_digest", "f" * 64),
        ("forward_attempt_id", "wrong"),
        ("restore_state_digest", "f" * 64),
    ):
        changed = {**q, k: v}
        apply(changed, fail=True)
    assert (
        json.loads(sql(f"SELECT kf_reservation.apply({literal(f)});", "kf_executor"))["status"]
        == "committed"
    )
    assert (
        sql(
            "SELECT version FROM kf_reservation.resource WHERE resource_id='"
            + q["resource"]["id"]
            + "';"
        )
        == "3"
    )
    passed.append(
        "inverse: concurrent replay, lost-reply query and conflicting/replacement "
        "identities cannot repeat either effect"
    )

    for key, value in (
        ("expected_version", 3),
        ("fence", 1),
        ("expires_at", 1),
        ("resource", {"id": "absent", "incarnation": "incarnation-1"}),
        ("forward_grant_digest", "e" * 64),
        ("forward_root_id", "foreign"),
        ("restore_state_digest", "d" * 64),
        ("contract_digest", "c" * 64),
    ):
        c, f, q = setup()
        bad = {**q, key: value}
        assert apply(bad)["status"] == "guard_rejected"
        assert apply(bad)["status"] == "guard_rejected"
        assert (
            sql(
                "SELECT version||':'||reservation FROM kf_reservation.resource "
                f"WHERE resource_id='{q['resource']['id']}';"
            )
            == "2:changed"
        )
    passed.append(
        "inverse: stale fence/version/deadline and substituted "
        "original/snapshot/resource refuse without restoring"
    )

    for mutation in (
        "version=version+1",
        "incarnation='recreated'",
        "active=false",
        "reservation='other'",
        "last_fence=last_fence+1",
    ):
        c, f, q = setup()
        assert barrier(c, f) is not None
        sql(
            "UPDATE kf_reservation.resource SET "
            + mutation
            + " WHERE resource_id='"
            + q["resource"]["id"]
            + "';"
        )
        assert barrier(c, f) is None
        assert apply(q)["status"] == "guard_rejected"
    c, f, q = setup(forward=False)
    assert barrier(c, f) is None and apply(q)["status"] == "guard_rejected"
    c, f, q = setup(forward=False)
    f["fence"] = 0
    # A valid request with stale version records a terminal guard rejection.
    f["fence"] = 1
    f["expected_version"] = 2
    assert (
        json.loads(sql(f"SELECT kf_reservation.apply({literal(f)});", "kf_executor"))["status"]
        == "guard_rejected"
    )
    assert barrier(c, f) is None and apply(q)["status"] == "guard_rejected"
    passed.append(
        "inverse: writer advance/recreation/inactive state and absent/noncommitted "
        "original cannot yield a barrier or restore"
    )

    c, f, q = setup()
    sql(
        "BEGIN; SET LOCAL ROLE kf_inverse_executor; SELECT "
        f"kf_compensation.apply({literal(q)}); ROLLBACK;"
    )
    assert not sql(
        "SELECT kf_compensation.lookup('inverse','" + q["attempt_id"] + "');", "kf_inverse_reader"
    )
    assert barrier(c, f) is not None and apply(q)["status"] == "committed"
    passed.append("inverse: caller rollback undoes both original result and restore")

    c, f, q = setup()
    q["expires_at"] = int(time.time() * 1000) + 450
    with ThreadPoolExecutor(max_workers=2) as pool:
        locked = pool.submit(
            sql,
            "BEGIN; SELECT 1 FROM kf_reservation.resource WHERE resource_id='"
            + q["resource"]["id"]
            + "' FOR UPDATE; SELECT pg_sleep(0.8); COMMIT;",
        )
        time.sleep(0.1)
        pending = pool.submit(apply, q)
        locked.result()
        assert pending.result()["status"] == "guard_rejected"
    assert barrier(c, f) is not None
    passed.append("inverse: deadline is rechecked after a contended resource lock")

    c, f, q = setup(forward=False)
    for role in ("kf_inverse_executor", "kf_inverse_reader", "kf_inverse_barrier", "kf_agent"):
        for statement in (
            "SELECT * FROM kf_compensation.snapshot;",
            "SELECT * FROM kf_compensation.attempt;",
            "UPDATE kf_reservation.resource SET reservation='bypass';",
            f"SELECT kf_compensation.capture({literal(c)});",
        ):
            sql(statement, role, True)
    sql(f"SELECT kf_compensation.apply({literal(q)});", "kf_inverse_reader", True)
    sql("SELECT kf_compensation.lookup('inverse','none');", "kf_inverse_executor", True)
    changed = copy.deepcopy(c)
    changed["restore_state_digest"] = "e" * 64
    sql(f"SELECT kf_compensation.capture({literal(changed)});", fail=True)
    assert json.loads(sql(f"SELECT kf_compensation.capture({literal(c)});")) == c
    passed.append(
        "inverse: owner-only immutable snapshot and separated "
        "execution/query/barrier functions deny bypass"
    )

    for mutation in (
        lambda q: {**q, "extra": True},
        lambda q: {**q, "fence": None},
        lambda q: {**q, "fence": True},
        lambda q: {**q, "expires_at": 9007199254740992},
        lambda q: {**q, "resource": {**q["resource"], "extra": True}},
        lambda q: {**q, "profile": "KF-POSTGRES-RESERVATION-0.1-draft"},
    ):
        apply(mutation(q), fail=True)
    passed.append(
        "inverse: closed bounded records reject null, unknown, unsafe and cross-profile inputs"
    )
    return passed

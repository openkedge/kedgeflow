#!/usr/bin/env python3
import json
from pathlib import Path

R = Path(__file__).resolve().parents[1]
s = json.loads((R / "results/final/summary.json").read_text())
rows = s["adversarial_experiments"]
manifest = {
    "schema": "kedgeflow-paper-experiments/v1",
    "run": s["finished_utc"],
    "source_commit": s["source_commit"],
    "fixture": (
        "deterministic compromised-agent output; successful redirection assumed; no actual model"
    ),
    "measurement_units": [
        "gateway calls",
        "direct-target HTTP/TLS probes",
        "independent authorization decision",
        "grant issuance",
        "successful claim",
        "dispatch authorization",
        "credentialed target requests",
        "mock commit",
        "successful response",
        "retained unknown",
    ],
    "counter_semantics": {
        "target_dispatches": (
            "legacy raw key: mock target requests after bearer check, before guard/mutation"
        ),
        "bypass_denials": (
            "three tested direct-target probes refused: two HTTP 401, one TLS failure; "
            "zero gateway calls"
        ),
    },
    "raw_log": "results/final/rust-tests.log",
    "raw_log_sha256": s["raw_log_sha256"],
    "test_code": "tests/paper_adversarial.rs",
    "test_code_sha256": s["adversarial_tests_sha256"],
    "scenarios": rows,
}
(R / "results/experiment-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
lines = [
    "# Executed adversarial results",
    "",
    f"Run UTC: {s['finished_utc']}. Source: `{s['source_commit']}`.",
    "",
    "Each row uses fresh etcd authority state and a fresh fenced mock target. Subject "
    "authentication, workload issuance, and independent policy are explicit synthetic fixtures. "
    "Broker/target requests use real mTLS. A successful claim and dispatch authorization are "
    "directly instrumented around the pinned ledger; credentialed target requests (the legacy raw "
    "key `target_dispatches`) and mock commits are recorded independently. Target requests count "
    "after the bearer check and "
    "before guard/mutation; they exclude refused direct probes.",
    "",
    "| Scenario / attacker surface | Expected and actual | Authorized / issued | GW / probes | "
    "Claims / dispatch authz / target requests / commits | Unknown | Evidence |",
    "|---|---|---|---|---|---|---|",
]
for r in rows:
    lines.append(
        f"| {r['experiment']} / {r['attacker_controlled_surface']} | "
        f"{r['expected_property']}; **{r['actual_result']}** | "
        f"{int(r['authorization_issued'])} / {r['grant_issued']} | "
        f"{r['gateway_requests']} / {3 if r['experiment'] == 'local_target_bypass' else 0} | "
        f"{r['claims']} / {r['dispatch_authorizations']} / "
        f"{r['target_dispatches']} / {r['mock_target_commits']} | "
        f"{r['outcome_remains_unknown']} | `{r['evidence']}` |"
    )
lines += [
    "",
    "The lost-response mock commits once while the gateway retains Unknown. The second call is "
    "refused; no status reconciliation is performed in that scenario. The permissive-policy case "
    "intentionally commits an undesirable action. Refusal and successful effects are distinct "
    "observations.",
    "",
    "The grant substitution case tampers with a signed payload. Cross-audience replay presents a "
    "correctly signed other-audience envelope against the gateway while legitimate local authority "
    "remains unused. These cases validate envelope integrity and audience enforcement, not a full "
    "malicious-issuer deployment.",
    "",
    "The bypass test rejects two mTLS requests (no token or caller token) with HTTP 401 and "
    "rejects one request without a client certificate at TLS. The test code shares a process and "
    "can access its synthetic target token; operating-system custody and a complete production "
    "writer inventory are untested.",
    "",
    "Untested: LLM attack success, control-plane compromise resilience, production credential "
    "isolation, native target adapters, multi-host failure/restore behavior, real authenticated "
    "target status integration, independent KedgeFlow interoperability, throughput and deployment "
    "cost.",
]
(R / "docs/experimental-results.md").write_text("\n".join(lines) + "\n")
# Every Rust test retained by suite/name with deliberately unmeasured per-stage fields.
v = json.loads((R / "results/verified-claims.json").read_text())
records = []
for suite in v["final"]["suites"]:
    for t in suite["tests"]:
        records.append(
            {
                "suite": suite["suite"],
                **t,
                "purpose": t["name"].replace("_", " "),
                "attacker_surface": "see retained test source; not uniformly instrumented",
                "authorization_issued": None,
                "grant_claimed": None,
                "dispatch_occurred": None,
                "mock_target_committed": None,
                "outcome_unknown": None,
                "stage_measurement": (
                    "per-scenario instrumented results available only for paper_adversarial; "
                    "other test stages must be read from code, not inferred from pass count"
                ),
                "evidence": "results/final/rust-tests.log",
            }
        )
(R / "results/test-inventory.json").write_text(
    json.dumps({"tests": records, "suites": v["final"]["suites"]}, indent=2) + "\n"
)

//! Actual pre-admission claim quota, source crash and final-slot competition.
//! No drain grant or physical mutation is issued by this source-only test.
use super::*;

fn request(r: &mut Ready, narrow_by: i64) -> preflight::Request {
    fresh(&mut r.physical);
    let mut proposal = r.physical.f.proposal.clone();
    let expiry = proposal["baseline_state"][0]["expires_at"]
        .as_i64()
        .unwrap();
    proposal["baseline_state"][0]["expires_at"] = json!(expiry - narrow_by);
    let enrollment = Store::new(r.physical.ledger.clone())
        .unwrap()
        .context
        .enrollment
        .clone();
    preflight::Request {
        profile: source::PROFILE.into(),
        enrollment_digest: enrollment.digest().unwrap(),
        signed_proposal: String::from_utf8(fixture::signed("proposal", proposal, 1)).unwrap(),
        requested_at: now(),
    }
}
async fn observe(
    process: &SourceProcess,
    query: &preflight::Request,
) -> (reqwest::StatusCode, Value) {
    let response = process
        .assembler
        .post(format!("{}/evidence", process.endpoint))
        .bearer_auth(EVIDENCE)
        .json(query)
        .send()
        .await
        .unwrap();
    (response.status(), response.json().await.unwrap())
}
fn verified_evidence(store: &Store, query: &preflight::Request, raw: Value) -> preflight::Evidence {
    let evidence: preflight::Evidence = serde_json::from_value(raw).unwrap();
    let proposal =
        kedgeflow::schema::verify_record(query.signed_proposal.as_bytes(), "proposal", &keys(1))
            .unwrap();
    evidence.validate(&store.context, &proposal, now()).unwrap();
    evidence
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_managed_preflight_four_claims_crash_last_slot_race_and_exhaustion() {
    assert_eq!(
        preflight::MAX_OBSERVATIONS,
        4,
        "unchanged pre-admission profile bound"
    );
    let (mut r, _, process, mut child) = Box::pin(setup_source(None)).await;
    let before = sql_rows(&r).await;
    let store = Store::new(r.physical.ledger.clone()).unwrap();
    let base = format!("{}/preflight", store.context.base());
    let interrupted = request(&mut r, 0);
    process.preflight_pause.armed.store(true, Ordering::SeqCst);
    let client = process.assembler.clone();
    let url = format!("{}/evidence", process.endpoint);
    let original = interrupted.clone();
    let pending = tokio::spawn(async move {
        client
            .post(url)
            .bearer_auth(EVIDENCE)
            .json(&original)
            .send()
            .await
    });
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while process.preflight_pause.intercepted.load(Ordering::SeqCst) == 0 {
        assert!(child.try_wait().unwrap().is_none());
        assert!(
            tokio::time::Instant::now() < until,
            "actual committed preflight claim not observed"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let committed = process
        .preflight_pause
        .committed
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    let claim: preflight::Claim = serde_json::from_value(committed.clone()).unwrap();
    claim.validate(&store.context).unwrap();
    assert_eq!(claim.sequence, 1);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    process.preflight_pause.release.notify_one();
    if let Ok(response) = pending.await.unwrap() {
        assert!(
            !response.status().is_success(),
            "killed source cannot deliver positive evidence"
        );
    }
    let head_key = format!("{base}/head");
    let original_head = r
        .physical
        .ledger
        .read_key(&head_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        kedgeflow::contracts::strict_value(&original_head).unwrap(),
        committed
    );
    assert!(
        r.physical
            .ledger
            .read_key(&format!("{base}/observations/{}", claim.digest().unwrap()))
            .await
            .unwrap()
            .is_none()
    );
    child = process.start().await;
    assert!(
        now() < claim.expires_at,
        "original consumed claim must still be live when replay is refused"
    );
    let (status, _) = observe(&process, &interrupted).await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
    store
        .context
        .admission_proposal(&interrupted, now())
        .unwrap();
    assert!(
        now() < claim.expires_at,
        "replay refusal must precede original claim expiry"
    );
    assert_eq!(
        r.physical
            .ledger
            .read_key(&head_key)
            .await
            .unwrap()
            .unwrap(),
        original_head,
        "restart/replay cannot refresh the consumed original query"
    );

    let mut observations = Vec::new();
    let mut queries = vec![interrupted.clone()];
    for sequence in 2..=3 {
        let query = request(&mut r, sequence);
        let (status, raw) = observe(&process, &query).await;
        assert_eq!(
            status,
            reqwest::StatusCode::OK,
            "new bounded source observation: {raw}"
        );
        let evidence = verified_evidence(&store, &query, raw);
        assert_eq!(evidence.statement.body.claim.sequence, sequence as u64);
        queries.push(query);
        observations.push(evidence);
    }
    let left = request(&mut r, 10);
    let mut right = left.clone();
    let mut proposal = kedgeflow::contracts::strict_value(right.signed_proposal.as_bytes())
        .unwrap()["payload"]
        .clone();
    let expiry = proposal["baseline_state"][0]["expires_at"]
        .as_i64()
        .unwrap();
    proposal["baseline_state"][0]["expires_at"] = json!(expiry - 1);
    right.signed_proposal = String::from_utf8(fixture::signed("proposal", proposal, 1)).unwrap();
    assert_ne!(left.signed_proposal, right.signed_proposal);
    let (left_result, right_result) =
        tokio::join!(observe(&process, &left), observe(&process, &right));
    let mut winner = None;
    let mut refused = None;
    for (query, (status, raw)) in [(&left, left_result), (&right, right_result)] {
        if status == reqwest::StatusCode::OK {
            assert!(
                winner.is_none(),
                "last native slot cannot admit both competitors"
            );
            let evidence = verified_evidence(&store, query, raw);
            assert_eq!(evidence.statement.body.claim.sequence, 4);
            winner = Some((query.clone(), evidence));
        } else {
            assert!(
                matches!(
                    status,
                    reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::SERVICE_UNAVAILABLE
                ),
                "unexpected source refusal: {status}; {raw}"
            );
            refused = Some(query.clone());
        }
    }
    let (winner_query, winner_evidence) =
        winner.expect("one actual final-slot observation must complete");
    let refused = refused.expect("other final-slot competitor must refuse");
    queries.push(left);
    queries.push(right);
    observations.push(winner_evidence.clone());
    let before_exhaustion = r
        .physical
        .ledger
        .read_key(&head_key)
        .await
        .unwrap()
        .unwrap();
    let exhausted = request(&mut r, 30);
    for query in [&refused, &exhausted] {
        assert_eq!(
            observe(&process, query).await.0,
            reqwest::StatusCode::FORBIDDEN
        );
    }
    let (status, replay) = observe(&process, &winner_query).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        replay,
        json!(winner_evidence),
        "successful original reply replay is unchanged and consumes no slot"
    );
    assert_eq!(
        r.physical
            .ledger
            .read_key(&head_key)
            .await
            .unwrap()
            .unwrap(),
        before_exhaustion
    );
    assert!(
        r.physical
            .ledger
            .read_key(&format!("{base}/events/0005"))
            .await
            .unwrap()
            .is_none()
    );
    let mut claims = Vec::<preflight::Claim>::new();
    for sequence in 1..=4 {
        let raw = r
            .physical
            .ledger
            .read_key(&format!("{base}/events/{sequence:04}"))
            .await
            .unwrap()
            .unwrap();
        let actual: preflight::Claim =
            serde_json::from_value(kedgeflow::contracts::strict_value(&raw).unwrap()).unwrap();
        actual.validate(&store.context).unwrap();
        assert_eq!(actual.sequence, sequence);
        assert_eq!(
            actual.previous_digest,
            claims.last().map(|claim| claim.digest().unwrap())
        );
        claims.push(actual);
    }
    assert_eq!(
        claims
            .iter()
            .map(|claim| &claim.proposal_digest)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
    assert_eq!(
        claims[0], claim,
        "the interrupted original claim remains unchanged"
    );
    for evidence in &observations {
        let retained = &evidence.statement.body.claim;
        assert_eq!(&claims[retained.sequence as usize - 1], retained);
        let raw = r
            .physical
            .ledger
            .read_key(&format!(
                "{base}/observations/{}",
                retained.digest().unwrap()
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            kedgeflow::contracts::strict_value(&raw).unwrap(),
            json!(evidence.statement),
            "successful response must be the actual retained signed source statement"
        );
    }
    let (_, refused_digest) = store.context.admission_proposal(&refused, now()).unwrap();
    assert!(
        claims
            .iter()
            .all(|claim| claim.proposal_digest != refused_digest)
    );
    assert!(
        store.status().await.unwrap().is_none(),
        "preflight exhaustion cannot create a drain origin or execution grant"
    );
    assert!(
        r.physical
            .ledger
            .read_key(&format!(
                "{}/issuance/{}",
                r.r.namespace, store.context.enrollment.operation_key
            ))
            .await
            .unwrap()
            .is_none(),
        "read-only source queries cannot issue a physical execution grant"
    );
    assert_eq!(before, sql_rows(&r).await);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    if let Some(output) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        let path = PathBuf::from(output).join("managed-preflight-boundaries.json");
        std::fs::write(path,canonical(&json!({"status":"passed","registration":r.r,
            "scope":"actual source-only pre-admission SQL observations/native CAS; no drain grant or physical execution qualification",
            "maximum_claims":4,"claims":claims,"successful_evidence":observations,"requests":queries,
            "exhausted_request":exhausted,"source_killed_after_actual_claim_commit":true,
            "interrupted_claim_consumed_without_observation":true,"replay_while_original_claim_live_refused":true,
            "last_slot_competitors":2,"last_slot_winners":1,"fifth_claim_absent":true,
            "sql_rows_unchanged":true,"drain_origin_absent":true,"head_after_exhaustion":String::from_utf8(before_exhaustion).unwrap()})).unwrap()).unwrap();
    }
}

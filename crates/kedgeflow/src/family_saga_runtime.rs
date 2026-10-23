//! Protected native composition storage and complete original history replay.
use crate::{
    action_domain::Lane,
    contracts::{canonical, strict_value},
    error::{Error, Result},
    family::{Access, Registration, Selection, State as FamilyState},
    family_saga::{Collected, MAX_HISTORY_BYTES, MAX_PROOF, PhaseEvent, PhaseState, Snapshot},
    ledger::{EtcdLedger, get, put, range_kv, record, value_eq},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
fn refused() -> Error {
    Error::Refused("native family saga storage or complete enrollment refused".into())
}
pub(crate) fn state_key(l: &EtcdLedger) -> String {
    format!("{}/family/saga/state", l.namespace())
}
pub(crate) fn proof_key(l: &EtcdLedger, d: &str) -> String {
    format!("{}/family/saga/proofs/{d}", l.namespace())
}
pub(crate) fn initial_writes(l: &EtcdLedger, r: &Registration) -> Result<Vec<Value>> {
    if r.composition.is_none() {
        return Ok(vec![]);
    }
    let mut writes = vec![put(&state_key(l), &record(&PhaseState::genesis(r)?)?)];
    for n in &r.composition.as_ref().ok_or_else(refused)?.nodes {
        if let Some(p) = &n.physical {
            writes.push(put(
                &format!(
                    "{}/family/drain/{}/contract",
                    l.namespace(),
                    n.operation_key
                ),
                &record(p)?,
            ));
        }
    }
    Ok(writes)
}
async fn raw_value(l: &EtcdLedger, key: &str, max: usize) -> Result<Vec<u8>> {
    let t = l.raw_txn(vec![], vec![get(key)], vec![]).await?;
    if !t.succeeded || t.responses.len() != 1 {
        return Err(refused());
    }
    let v = range_kv(&t.responses[0])?.ok_or_else(refused)?.value;
    if v.len() > max {
        return Err(refused());
    }
    Ok(v)
}
pub(crate) async fn retained(
    l: &EtcdLedger,
    r: &Registration,
) -> Result<(PhaseState, BTreeMap<String, Snapshot>, Vec<Value>)> {
    let raw = raw_value(l, &state_key(l), crate::family_saga_phase::MAX_STATE).await?;
    let s: PhaseState = serde_json::from_value(strict_value(&raw)?)?;
    if record(&s)?.as_bytes() != raw {
        return Err(refused());
    }
    let mut references = BTreeSet::new();
    for e in &s.events {
        if let PhaseEvent::Owner { intent, .. } = e
            && let Some(d) = &intent.payload.proof_digest
        {
            references.insert(d.clone());
        }
    }
    if let Some(d) = &s.snapshot_digest {
        references.insert(d.clone());
    }
    if s.events.len() > crate::family_saga_phase::MAX_EVENTS
        || references.len() > crate::family_saga_phase::MAX_EVENTS
    {
        return Err(refused());
    }
    let mut captures = Vec::new();
    let mut total = 0usize;
    for d in references {
        if !crate::grant_reference::valid_reference(&d) {
            return Err(refused());
        }
        let bytes = raw_value(l, &proof_key(l, &d), MAX_PROOF + 4096).await?;
        total = total.checked_add(bytes.len()).ok_or_else(refused)?;
        if total > MAX_HISTORY_BYTES {
            return Err(refused());
        }
        captures.push((d, bytes));
    }
    // Complete native signature/history replay is CPU work, not a continuation
    // of the already deep admission/issuance future. Keep it off the async IO
    // worker's stack and reactor; no live fact or successful comparison is cached.
    let registration = r.clone();
    let phase_raw = raw.clone();
    let (s, proofs) = tokio::task::spawn_blocking(move || -> Result<_> {
        use crate::family_saga_cache::{ByteCache, key};
        use std::sync::{Mutex, OnceLock};
        type Verified = (PhaseState, BTreeMap<String, Snapshot>);
        static CACHE: OnceLock<Mutex<ByteCache<Verified>>> = OnceLock::new();
        let pinned = registration.canonical_record()?;
        let mut parts = vec![pinned.as_bytes(), phase_raw.as_slice()];
        for (d, bytes) in &captures {
            parts.extend([d.as_bytes(), bytes.as_slice()]);
        }
        let digest = key("verified-family-native-history", &parts);
        let cache = CACHE.get_or_init(|| Mutex::new(ByteCache::new(8)));
        if let Some(verified) = cache.lock().map_err(|_| refused())?.get(&digest) {
            return Ok(verified);
        }
        let weight = total + pinned.len() + phase_raw.len();
        let mut proofs = BTreeMap::new();
        for (d, bytes) in captures {
            let c = Collected::decode(&bytes)?;
            c.verify(&registration)?;
            if c.snapshot.digest()? != d || canonical(&json!(c))? != bytes {
                return Err(refused());
            }
            proofs.insert(d, c.snapshot);
        }
        s.verify(&registration, &proofs)?;
        cache
            .lock()
            .map_err(|_| refused())?
            .insert(digest, weight, (s.clone(), proofs.clone()));
        Ok((s, proofs))
    })
    .await
    .map_err(|_| Error::Unavailable("native family history replay worker failed".into()))??;
    Ok((
        s,
        proofs,
        vec![value_eq(
            &state_key(l),
            std::str::from_utf8(&raw).map_err(|_| refused())?,
        )],
    ))
}
pub(crate) fn child_ledger(
    base: &EtcdLedger,
    r: &Registration,
    child: &str,
    inverse: bool,
) -> Result<EtcdLedger> {
    let c = r.child(child)?;
    let n = r.composition.as_ref().ok_or_else(refused)?.node(child)?;
    let mut l = base.clone();
    // Only protected catalog pins select these contexts, never an intent/task.
    l.family = None;
    l.action_domain = None;
    l.reservation = None;
    l.inverse_execution = None;
    l.required_trust_digest = None;
    l = l.requiring_control(Some(n.trust_digest(inverse)?));
    if let Some(t) = &c.topology {
        l = l.with_action_domain(crate::action_domain::Selection {
            topology: t.clone(),
            lane: if inverse {
                Lane::Inverse
            } else {
                Lane::Forward
            },
        })?;
    }
    if inverse {
        let t = n.compound()?.ok_or_else(refused)?;
        let config: crate::compensation_execution::ExecutionConfig = serde_json::from_value(
            json!({"profile":crate::compensation_execution::PROFILE,"contract":t.contract,"forward":n.forward_trust,"outcome_keys":t.inverse.outcome_keys.iter().map(|(id,k)|(id.clone(),base64::Engine::encode(&base64::engine::general_purpose::STANDARD,k.as_bytes()))).collect::<BTreeMap<_,_>>(),"source_id":t.inverse.source_id}),
        )?;
        l = config.attach(l)?;
    }
    Selection {
        registration: r.clone(),
        child_id: child.into(),
    }
    .attach(l)
}
pub(crate) async fn authority(
    l: &EtcdLedger,
    r: &Registration,
    family: &FamilyState,
    child: &str,
) -> Result<(Vec<Value>, Option<crate::family_saga_bindings::View>)> {
    let Some(plan) = &r.composition else {
        return Ok((vec![], None));
    };
    if family.attachments.len() != r.children.len()
        || r.children
            .iter()
            .any(|c| !family.attachments.contains_key(&c.id))
    {
        return Err(refused());
    }
    let (state, proofs, mut compare) = retained(l, r).await?;
    // The initial separately sealed complete inventory establishes that every
    // immutable native enrollment/qualifier is installed before any leaf runs.
    // Original native authority records retain this exact phase head.
    if state.members.len() != plan.nodes.len() || state.snapshot_digest.is_none() {
        return Err(refused());
    }
    if l.action_domain
        .as_ref()
        .is_some_and(|s| s.lane == Lane::Inverse)
    {
        state.inverse_ready(plan, child)?;
    } else {
        state.forward_ready(plan, child)?;
    }
    let mut markers = Vec::new();
    if l.action_domain
        .as_ref()
        .is_some_and(|s| s.lane == Lane::Inverse)
    {
        // A newly refreshed local qualification must be observed globally
        // before a short-lived original inverse grant can be issued from it.
        // Otherwise issuance could consume the fixed operation while claim
        // necessarily refuses an unobserved qualification.
        let d = state.snapshot_digest.as_ref().ok_or_else(refused)?;
        let q = proofs
            .get(d)
            .ok_or_else(refused)?
            .members
            .get(child)
            .ok_or_else(refused)?
            .compound
            .as_ref()
            .ok_or_else(refused)?
            .evidence
            .qualifications
            .last()
            .ok_or_else(refused)?;
        let contract = r.child(child)?.inverse.as_ref().ok_or_else(refused)?;
        markers.push((format!("{}/inverse-contracts/{}/head",l.namespace(),contract.forward_operation_key),record(&json!({"profile":crate::compensation::PROFILE,"sequence":q.sequence,"record_digest":q.digest()?}))?));
    }
    compare.extend(check_markers(l, &markers).await?);
    let inverse = l
        .action_domain
        .as_ref()
        .is_some_and(|s| s.lane == Lane::Inverse);
    let frame = crate::family_saga_bindings::View {
        registration_digest: r.digest()?,
        family_head: family.head.clone(),
        phase_head: state.head,
        child_id: child.into(),
        lane: if inverse { "inverse" } else { "forward" }.into(),
        qualification_digest: if inverse {
            state
                .members
                .get(child)
                .ok_or_else(refused)?
                .qualification
                .clone()
        } else {
            None
        },
    };
    Ok((compare, Some(frame)))
}
pub(crate) async fn enrollment(l: &EtcdLedger, r: &Registration) -> Result<Vec<Value>> {
    let plan = r.composition.as_ref().ok_or_else(refused)?;
    let mut markers = Vec::new();
    for c in &r.children {
        let f = child_ledger(l, r, &c.id, false)?;
        let rr = &c.reservation;
        markers.push((crate::reserved_leaf::required_key(&f,&rr.scope.conflict_domain),record(&json!({"profile":rr.profile,"root_id":rr.root_id,"root_generation":1,"registration_digest":rr.digest()?}))?));
        if let Some(contract) = &c.inverse {
            let q = crate::compensation::Qualifier::new(
                f,
                contract.clone(),
                plan.node(&c.id)?.forward()?,
            )?;
            markers.push((
                format!(
                    "{}/inverse-contracts/{}/contract",
                    l.namespace(),
                    contract.forward_operation_key
                ),
                q.marker()?,
            ));
        }
    }
    check_markers(l, &markers).await
}
async fn check_markers(l: &EtcdLedger, markers: &[(String, String)]) -> Result<Vec<Value>> {
    if markers.is_empty() {
        return Ok(vec![]);
    }
    let mut compare = Vec::new();
    let read = l
        .raw_txn(
            vec![],
            markers.iter().map(|(k, _)| get(k)).collect(),
            vec![],
        )
        .await?;
    if !read.succeeded || read.responses.len() != markers.len() {
        return Err(refused());
    }
    for ((key, expected), response) in markers.iter().zip(&read.responses) {
        if range_kv(response)?.is_none_or(|v| v.value != expected.as_bytes()) {
            return Err(refused());
        }
        compare.push(value_eq(key, expected));
    }
    Ok(compare)
}

pub(crate) async fn claim(
    l: &EtcdLedger,
    binding: crate::compensation_execution::Binding,
    attempt: &str,
    claimed_at: i64,
) -> Result<crate::reserved_leaf::Change> {
    let empty = || crate::reserved_leaf::Change {
        compare: vec![],
        writes: vec![],
        newly_allocated: false,
    };
    let Some(access) = &l.family else {
        return Ok(empty());
    };
    let Access::Child(selection) = access.as_ref() else {
        return Err(refused());
    };
    let r = &selection.registration;
    if r.composition.is_none() {
        return Ok(empty());
    }
    let (mut state, proofs, mut compare) = retained(l, r).await?;
    let expires_at = binding.payload.expires_at;
    let family_key = format!("{}/family/state", l.namespace());
    let family_raw = raw_value(l, &family_key, crate::family::MAX_BYTES).await?;
    let registration = r.clone();
    let child = selection.child_id.clone();
    let attempt = attempt.to_owned();
    let (state, family) = tokio::task::spawn_blocking(move || -> Result<_> {
        let family: FamilyState = serde_json::from_value(strict_value(&family_raw)?)?;
        family.verify(&registration)?;
        state.claim(
            &registration,
            &child,
            &attempt,
            binding,
            &proofs,
            claimed_at,
        )?;
        reserve_wire(&registration, &family, &state)?;
        Ok((record(&state)?, record(&family)?))
    })
    .await
    .map_err(|_| Error::Unavailable("native family claim replay worker failed".into()))??;
    compare.push(value_eq(&family_key, &family));
    let now = l.authority_clock.now_ms();
    if now < claimed_at || now >= expires_at {
        return Err(refused());
    }
    Ok(crate::reserved_leaf::Change {
        compare,
        writes: vec![put(&state_key(l), &state)],
        newly_allocated: false,
    })
}

/// Reserve actual encoded future capture/phase transaction space, in addition
/// to journal/proof storage. Administrative family growth shares this budget.
pub(crate) fn reserve_wire(
    r: &Registration,
    family: &FamilyState,
    state: &PhaseState,
) -> Result<()> {
    let phase = "x".repeat(state.future_state_bytes(r)?);
    let family = format!("{}{}", record(family)?, "x".repeat(4096));
    let epoch = "x".repeat(512);
    let proof = "x".repeat(MAX_PROOF + 4096);
    let key = format!("{}/family/saga/state", r.namespace);
    let ek = format!("{}/family/saga/epoch", r.namespace);
    let compare = vec![
        value_eq(&format!("{}/family/required", r.namespace), &record(r)?),
        value_eq(&format!("{}/family/state", r.namespace), &family),
        value_eq(&key, &phase),
        value_eq(&ek, &epoch),
    ];
    let writes = vec![
        put(&key, &phase),
        put(
            &format!("{}/family/saga/proofs/{}", r.namespace, "f".repeat(64)),
            &proof,
        ),
        put(&ek, &epoch),
    ];
    if canonical(&json!({"compare":compare,"success":writes,"failure":[]}))?.len()
        > (1 << 20) - (64 << 10)
    {
        return Err(Error::Refused(
            "family saga future capture transaction capacity is reserved".into(),
        ));
    }
    Ok(())
}
pub(crate) async fn reserve_family(
    l: &EtcdLedger,
    r: &Registration,
    next: &FamilyState,
) -> Result<Vec<Value>> {
    if r.composition.is_none() {
        return Ok(vec![]);
    }
    let (state, _, compare) = retained(l, r).await?;
    reserve_wire(r, next, &state)?;
    Ok(compare)
}

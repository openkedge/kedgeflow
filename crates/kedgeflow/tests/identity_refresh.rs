//! Generated signing keys and protected-source fixtures; no production publisher.
#[path = "support/exchange_identity.rs"]
mod identity;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use identity::{ACTOR_AUDIENCE, AUDIENCE, Fixture, ISSUER, NOW};
use kedgeflow::{
    broker_authorization::ExchangeIdentityProvider,
    contracts::strict_value,
    error::{Error, Result},
    identity_refresh::{
        RealmPins, RefreshHead, RefreshSource, RefreshingIdentityProvider, SignedSnapshot,
        sign_snapshot, validate,
    },
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
struct Source {
    head: Mutex<Vec<u8>>,
    snapshot: Mutex<Vec<u8>>,
    fail: AtomicBool,
    reads: AtomicUsize,
    next: Mutex<Option<RefreshHead>>,
}
impl Source {
    fn new(record: &SignedSnapshot, head: &RefreshHead) -> Self {
        Self {
            head: Mutex::new(serde_json::to_vec(head).unwrap()),
            snapshot: Mutex::new(serde_json::to_vec(record).unwrap()),
            fail: AtomicBool::new(false),
            reads: AtomicUsize::new(0),
            next: Mutex::new(None),
        }
    }
    fn publish(&self, record: &SignedSnapshot, head: &RefreshHead) {
        *self.snapshot.lock().unwrap() = serde_json::to_vec(record).unwrap();
        *self.head.lock().unwrap() = serde_json::to_vec(head).unwrap();
    }
    fn head(&self, head: &RefreshHead) {
        *self.head.lock().unwrap() = serde_json::to_vec(head).unwrap();
    }
}
#[async_trait]
impl RefreshSource for Source {
    async fn head(&self) -> Result<Vec<u8>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error::Unavailable("software source unavailable".into()));
        }
        Ok(self.head.lock().unwrap().clone())
    }
    async fn snapshot(&self) -> Result<Vec<u8>> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error::Unavailable("software source unavailable".into()));
        }
        let raw = self.snapshot.lock().unwrap().clone();
        if let Some(head) = self.next.lock().unwrap().take() {
            self.head(&head);
        }
        Ok(raw)
    }
}
fn pins() -> RealmPins {
    RealmPins {
        issuer: ISSUER.into(),
        subject_audience: AUDIENCE.into(),
        actor_audience: ACTOR_AUDIENCE.into(),
    }
}
fn provider(source: Arc<Source>, key: &SigningKey, floor: u64) -> RefreshingIdentityProvider {
    RefreshingIdentityProvider::new(
        source,
        pins(),
        "operator-refresh".into(),
        BTreeMap::from([("refresh-1".into(), key.verifying_key())]),
        BTreeSet::new(),
        floor,
    )
    .unwrap()
}
fn records(f: &Fixture, key: &SigningKey) -> (SignedSnapshot, RefreshHead) {
    sign_snapshot(
        f.snapshot.clone(),
        "operator-refresh".into(),
        "refresh-1".into(),
        key,
    )
    .unwrap()
}
#[tokio::test]
async fn signed_refresh_reloads_each_exchange_and_preserves_exact_delegation() {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[15; 32]);
    let (r, h) = records(&f, &key);
    let source = Arc::new(Source::new(&r, &h));
    let p = provider(source.clone(), &key, 1);
    p.check_material().await.unwrap();
    let (s, a) = f.tokens();
    let old = f.provider().verify(&s, &a, NOW).await.unwrap();
    let fresh = p.verify(&s, &a, NOW).await.unwrap();
    assert_eq!(
        old.identity.delegation_digest,
        fresh.identity.delegation_digest
    );
    assert_eq!(source.reads.load(Ordering::SeqCst), 4);
    let mut next = f.snapshot.clone();
    next.epoch = 2;
    next.expires_at = NOW + 200000;
    let (r, h) = sign_snapshot(next, "operator-refresh".into(), "refresh-1".into(), &key).unwrap();
    source.publish(&r, &h);
    assert!(p.verify(&s, &a, NOW + 120000).await.is_ok());
}
#[tokio::test]
async fn signature_authority_realm_epoch_and_digest_substitutions_refuse() {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[15; 32]);
    let (r, h) = records(&f, &key);
    let (s, a) = f.tokens();
    for field in [
        "signature",
        "key_id",
        "authority_id",
        "realm_digest",
        "epoch",
        "snapshot_digest",
        "snapshot",
    ] {
        let source = Arc::new(Source::new(&r, &h));
        let p = provider(source.clone(), &key, 1);
        let mut v = serde_json::to_value(&r).unwrap();
        match field {
            "epoch" => v[field] = json!(2),
            "snapshot" => v[field]["issuer"] = json!("https://other.test"),
            "signature" => v[field] = json!(URL_SAFE_NO_PAD.encode([0; 64])),
            "realm_digest" | "snapshot_digest" => v[field] = json!("a".repeat(64)),
            _ => v[field] = json!("other"),
        };
        *source.snapshot.lock().unwrap() = serde_json::to_vec(&v).unwrap();
        assert!(p.verify(&s, &a, NOW).await.is_err(), "{field}");
    }
    let other = SigningKey::from_bytes(&[16; 32]);
    let (r, h) = records(&f, &other);
    assert!(
        provider(Arc::new(Source::new(&r, &h)), &key, 1)
            .verify(&s, &a, NOW)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn signed_wrong_realm_and_subject_role_overlap_are_not_authorized() {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[15; 32]);
    let (s, a) = f.tokens();
    let mut wrong = f.snapshot.clone();
    wrong.issuer = "https://other.test".into();
    for r in &mut wrong.registrations {
        r.subject.iss = wrong.issuer.clone();
    }
    let (r, mut h) =
        sign_snapshot(wrong, "operator-refresh".into(), "refresh-1".into(), &key).unwrap();
    h.realm_digest = pins().digest().unwrap();
    assert!(
        provider(Arc::new(Source::new(&r, &h)), &key, 1)
            .verify(&s, &a, NOW)
            .await
            .is_err()
    );
    let mut overlap = f.snapshot.clone();
    overlap.subject_keys[0].public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
    let (r, h) =
        sign_snapshot(overlap, "operator-refresh".into(), "refresh-1".into(), &key).unwrap();
    assert!(
        provider(Arc::new(Source::new(&r, &h)), &key, 1)
            .check_material()
            .await
            .is_err()
    );
    let (r, h) = records(&f, &key);
    let p = RefreshingIdentityProvider::new(
        Arc::new(Source::new(&r, &h)),
        pins(),
        "operator-refresh".into(),
        BTreeMap::from([("refresh-1".into(), key.verifying_key())]),
        BTreeSet::from([f.subject.verifying_key().to_bytes()]),
        1,
    )
    .unwrap();
    assert!(p.check_material().await.is_err());
    assert!(
        RefreshingIdentityProvider::new(
            Arc::new(Source::new(&r, &h)),
            pins(),
            "operator-refresh".into(),
            BTreeMap::from([("refresh-1".into(), key.verifying_key())]),
            BTreeSet::from([key.verifying_key().to_bytes()]),
            1
        )
        .is_err()
    );
}
#[tokio::test]
async fn missing_higher_publication_is_remembered_and_rollback_stays_refused() {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[15; 32]);
    let (r, h) = records(&f, &key);
    let source = Arc::new(Source::new(&r, &h));
    let p = provider(source.clone(), &key, 1);
    let (s, a) = f.tokens();
    assert!(p.verify(&s, &a, NOW).await.is_ok());
    let mut next = f.snapshot.clone();
    next.epoch = 2;
    let (_, higher) =
        sign_snapshot(next, "operator-refresh".into(), "refresh-1".into(), &key).unwrap();
    source.head(&higher);
    assert!(p.verify(&s, &a, NOW).await.is_err());
    source.head(&h);
    assert!(p.clone().verify(&s, &a, NOW).await.is_err());
    assert!(provider(source, &key, 2).check_material().await.is_err());
}
#[tokio::test]
async fn same_epoch_split_head_refuses_without_replacing_approved_digest() {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[15; 32]);
    let (r, h) = records(&f, &key);
    let source = Arc::new(Source::new(&r, &h));
    let p = provider(source.clone(), &key, 1);
    p.check_material().await.unwrap();
    let mut changed = f.snapshot.clone();
    changed.expires_at += 1;
    let (other, head) =
        sign_snapshot(changed, "operator-refresh".into(), "refresh-1".into(), &key).unwrap();
    source.publish(&other, &head);
    assert!(p.check_material().await.is_err());
    source.publish(&r, &h);
    assert!(p.check_material().await.is_ok());
}
#[tokio::test]
async fn head_change_during_verification_refuses_and_remembers_new_epoch() {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[15; 32]);
    let (r, h) = records(&f, &key);
    let source = Arc::new(Source::new(&r, &h));
    let p = provider(source.clone(), &key, 1);
    let mut next = f.snapshot.clone();
    next.epoch = 2;
    let (new, new_head) =
        sign_snapshot(next, "operator-refresh".into(), "refresh-1".into(), &key).unwrap();
    *source.next.lock().unwrap() = Some(new_head.clone());
    let (s, a) = f.tokens();
    assert!(p.verify(&s, &a, NOW).await.is_err());
    source.publish(&r, &h);
    assert!(p.verify(&s, &a, NOW).await.is_err());
    source.publish(&new, &new_head);
    assert!(p.verify(&s, &a, NOW).await.is_ok());
}
#[tokio::test]
async fn unavailable_source_and_expired_snapshot_never_fall_back_to_cached_trust() {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[15; 32]);
    let (r, h) = records(&f, &key);
    let source = Arc::new(Source::new(&r, &h));
    let p = provider(source.clone(), &key, 1);
    let (s, a) = f.tokens();
    assert!(p.verify(&s, &a, NOW).await.is_ok());
    source.fail.store(true, Ordering::SeqCst);
    assert!(p.verify(&s, &a, NOW).await.is_err());
    source.fail.store(false, Ordering::SeqCst);
    assert!(p.verify(&s, &a, NOW + 120000).await.is_err());
    *source.snapshot.lock().unwrap() = vec![];
    assert!(p.verify(&s, &a, NOW).await.is_err());
}
#[tokio::test]
async fn live_withdrawal_and_key_retirement_refuse_original_tokens() {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[15; 32]);
    let (r, h) = records(&f, &key);
    let source = Arc::new(Source::new(&r, &h));
    let p = provider(source.clone(), &key, 1);
    let (s, a) = f.tokens();
    assert!(p.verify(&s, &a, NOW).await.is_ok());
    let mut withdrawn = f.snapshot.clone();
    withdrawn.epoch = 2;
    withdrawn.registrations[0].workload_id = "spiffe://test/withdrawn".into();
    let (r, h) = sign_snapshot(
        withdrawn,
        "operator-refresh".into(),
        "refresh-1".into(),
        &key,
    )
    .unwrap();
    source.publish(&r, &h);
    assert!(p.verify(&s, &a, NOW).await.is_err());
    let mut retired = f.snapshot.clone();
    retired.epoch = 3;
    retired.actor_keys[0].kid = "retired-old-key-id".into();
    let (r, h) =
        sign_snapshot(retired, "operator-refresh".into(), "refresh-1".into(), &key).unwrap();
    source.publish(&r, &h);
    assert!(p.verify(&s, &a, NOW).await.is_err());
}
#[tokio::test]
async fn replicas_and_restart_use_the_same_retained_exact_head() {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[15; 32]);
    let (r, h) = records(&f, &key);
    let source = Arc::new(Source::new(&r, &h));
    let a = provider(source.clone(), &key, 1);
    let b = provider(source.clone(), &key, 1);
    let (s, actor) = f.tokens();
    let (x, y) = tokio::join!(a.verify(&s, &actor, NOW), b.verify(&s, &actor, NOW));
    assert!(x.is_ok() && y.is_ok());
    let mut next = f.snapshot.clone();
    next.epoch = 2;
    let (r, h) = sign_snapshot(next, "operator-refresh".into(), "refresh-1".into(), &key).unwrap();
    source.publish(&r, &h);
    assert!(
        provider(source.clone(), &key, 2)
            .verify(&s, &actor, NOW)
            .await
            .is_ok()
    );
    assert!(a.verify(&s, &actor, NOW).await.is_ok());
    assert!(b.verify(&s, &actor, NOW).await.is_ok());
}
#[tokio::test]
async fn closed_duplicate_and_oversized_records_refuse() {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[15; 32]);
    let (r, h) = records(&f, &key);
    let source = Arc::new(Source::new(&r, &h));
    let p = provider(source.clone(), &key, 1);
    let mut v = serde_json::to_value(&h).unwrap();
    v["extra"] = json!(true);
    assert!(validate(&v).is_err());
    let raw =
        serde_json::to_string(&h)
            .unwrap()
            .replacen("\"epoch\":1", "\"epoch\":1,\"epoch\":1", 1);
    assert!(strict_value(raw.as_bytes()).is_err());
    *source.head.lock().unwrap() = raw.into_bytes();
    assert!(p.check_material().await.is_err());
    source.head(&h);
    *source.snapshot.lock().unwrap() = vec![b' '; (1 << 20) + 16385];
    assert!(p.check_material().await.is_err());
    *source.head.lock().unwrap() = vec![b' '; 16385];
    assert!(p.check_material().await.is_err());
}

#[tokio::test]
async fn snapshot_digest_binds_exact_embedded_arrays_before_typed_normalization() {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[15; 32]);
    let (record, head) = records(&f, &key);
    let mut value = serde_json::to_value(&record).unwrap();
    value["snapshot"]["registrations"][0]["allowed_scopes"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let resign = |v: &mut serde_json::Value| {
        let mut unsigned = v.clone();
        unsigned.as_object_mut().unwrap().remove("signature");
        let mut message = kedgeflow::identity_refresh::PROFILE.as_bytes().to_vec();
        message.push(0);
        message.extend(kedgeflow::contracts::canonical(&unsigned).unwrap());
        v["signature"] = json!(URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes()));
    };
    resign(&mut value);
    let source = Arc::new(Source::new(&record, &head));
    *source.snapshot.lock().unwrap() = serde_json::to_vec(&value).unwrap();
    let (subject, actor) = f.tokens();
    assert!(
        provider(source.clone(), &key, 1)
            .verify(&subject, &actor, NOW)
            .await
            .is_err()
    );
    let exact = kedgeflow::contracts::digest("identity-snapshot", &value["snapshot"]).unwrap();
    value["snapshot_digest"] = json!(exact);
    resign(&mut value);
    let mut head = head;
    head.snapshot_digest = exact;
    source.head(&head);
    *source.snapshot.lock().unwrap() = serde_json::to_vec(&value).unwrap();
    assert!(
        provider(source, &key, 1)
            .verify(&subject, &actor, NOW)
            .await
            .is_ok()
    );
}

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use kedgeflow::{contracts::Resource, current_reservation as sql, family_saga::ObserverPin};
use std::collections::BTreeMap;
fn pin(id: &str, n: u8) -> ObserverPin {
    ObserverPin {
        id: id.into(),
        keys: BTreeMap::from([(
            "key".into(),
            STANDARD.encode(SigningKey::from_bytes(&[n; 32]).verifying_key().as_bytes()),
        )]),
    }
}
pub fn registration() -> sql::Registration {
    sql::Registration {
        profile: sql::PROFILE.into(),
        tenant: "tenant-42".into(),
        forward_child_id: "sql".into(),
        forward_operation_key: "c".repeat(64),
        forward_reservation_root_id: "root-sql".into(),
        compensation_contract_digest: "d".repeat(64),
        resource: Resource {
            id: "orders-db".into(),
            incarnation: "db-1".into(),
        },
        endpoint: "https://sql.test/current".into(),
        evidence_endpoint: "https://sql.test/evidence".into(),
        provider: pin("sql-provider", 94),
        storage: sql::StorageBoundary {
            storage_id: "storage-1".into(),
            generation: 1,
            identity: sql::StorageIdentity {
                database: "postgres".into(),
                database_oid: 5,
                postmaster_started_at_us: 500_000,
            },
            owner: pin("storage-owner", 95),
            restore_protocol_digest: "e".repeat(64),
            coordinated_writers: vec!["sql-forward".into(), "sql-inverse".into()],
            external_writers: vec!["database-owner".into()],
        },
        maximum_age_ms: 5000,
        request_timeout_ms: 5000,
    }
}

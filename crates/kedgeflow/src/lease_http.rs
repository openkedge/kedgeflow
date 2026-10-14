//! Closed, separately versioned carriage; old control requests stay unchanged.
use crate::admission::StoredAdmissionPacket;
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub(crate) enum Request {
    #[serde(rename = "prevalidate")]
    Prevalidate {
        profile: String,
        request_id: String,
        proposal: String,
        descriptor: String,
        manifest: String,
        witnesses: Vec<String>,
    },
    #[serde(rename = "admit")]
    Admit {
        profile: String,
        request_id: String,
        proposal: String,
        descriptor: String,
        manifest: String,
        witnesses: Vec<String>,
        lease: String,
    },
}
impl Request {
    pub fn packet(self) -> (String, StoredAdmissionPacket, bool) {
        match self {
            Self::Prevalidate {
                profile,
                request_id,
                proposal,
                descriptor,
                manifest,
                witnesses,
            } => {
                debug_assert_eq!(profile, crate::leases::PROFILE);
                (
                    request_id,
                    StoredAdmissionPacket {
                        proposal,
                        descriptor,
                        manifest,
                        witnesses,
                        lease: None,
                    },
                    true,
                )
            }
            Self::Admit {
                profile,
                request_id,
                proposal,
                descriptor,
                manifest,
                witnesses,
                lease,
            } => {
                debug_assert_eq!(profile, crate::leases::PROFILE);
                (
                    request_id,
                    StoredAdmissionPacket {
                        proposal,
                        descriptor,
                        manifest,
                        witnesses,
                        lease: Some(lease),
                    },
                    false,
                )
            }
        }
    }
}
pub(crate) fn validate(raw: &[u8]) -> bool {
    static PIN: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let pin = PIN.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/static-lease-http-v0.1.schema.json"
            ))
            .expect("lease schema"),
        )
        .expect("local lease schema")
    });
    crate::contracts::strict_value(raw).is_ok_and(|v| pin.is_valid(&v))
}

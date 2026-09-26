use latch_approvals::{ExecutionPermit, PermitSource};
use latch_audit::{AuditEntryInput, AuditError, AuditEventType, AuditLedger};
use latch_core::{ActionRequest, Resource};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const OPERATION: &str = "secret.use";
pub const RESOURCE_KIND: &str = "secret";

pub struct SecretRegistration {
    credential_ref: String,
    material: Vec<u8>,
    allowed_consumers: BTreeSet<String>,
    version: u64,
}

impl SecretRegistration {
    pub fn new(
        credential_ref: impl Into<String>,
        material: impl Into<Vec<u8>>,
        allowed_consumers: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        let credential_ref = credential_ref.into();
        validate_identifier("credential_ref", &credential_ref)?;
        let material = material.into();
        if material.is_empty() {
            return Err(SecretError::InvalidRegistration(
                "secret material must not be empty".into(),
            ));
        }
        let allowed_consumers = allowed_consumers
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        if allowed_consumers.is_empty() {
            return Err(SecretError::InvalidRegistration(
                "at least one consumer must be allowed".into(),
            ));
        }
        for consumer in &allowed_consumers {
            validate_identifier("consumer", consumer)?;
        }

        Ok(Self {
            credential_ref,
            material,
            allowed_consumers,
            version: 1,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretDescriptor {
    pub credential_ref: String,
    pub version: u64,
    pub allowed_consumers: Vec<String>,
}

struct SecretRecord {
    material: Vec<u8>,
    allowed_consumers: BTreeSet<String>,
    version: u64,
}

impl Drop for SecretRecord {
    fn drop(&mut self) {
        self.material.fill(0);
    }
}

pub struct SecretBroker {
    secrets: BTreeMap<String, SecretRecord>,
}

impl fmt::Debug for SecretBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBroker")
            .field("credential_refs", &self.secrets.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SecretBroker {
    pub fn new(registrations: impl IntoIterator<Item = SecretRegistration>) -> Result<Self> {
        let mut secrets = BTreeMap::new();
        for registration in registrations {
            let SecretRegistration {
                credential_ref,
                material,
                allowed_consumers,
                version,
            } = registration;
            if secrets
                .insert(
                    credential_ref.clone(),
                    SecretRecord {
                        material,
                        allowed_consumers,
                        version,
                    },
                )
                .is_some()
            {
                return Err(SecretError::DuplicateCredential(credential_ref));
            }
        }
        if secrets.is_empty() {
            return Err(SecretError::InvalidRegistration(
                "secret broker requires at least one credential".into(),
            ));
        }
        Ok(Self { secrets })
    }

    pub fn descriptor(&self, credential_ref: &str) -> Result<SecretDescriptor> {
        let record = self
            .secrets
            .get(credential_ref)
            .ok_or_else(|| SecretError::UnknownCredential(credential_ref.into()))?;
        Ok(SecretDescriptor {
            credential_ref: credential_ref.into(),
            version: record.version,
            allowed_consumers: record.allowed_consumers.iter().cloned().collect(),
        })
    }

    pub fn descriptors(&self) -> Vec<SecretDescriptor> {
        self.secrets
            .iter()
            .map(|(credential_ref, record)| SecretDescriptor {
                credential_ref: credential_ref.clone(),
                version: record.version,
                allowed_consumers: record.allowed_consumers.iter().cloned().collect(),
            })
            .collect()
    }

    pub fn rotate(
        &mut self,
        credential_ref: &str,
        new_material: impl Into<Vec<u8>>,
    ) -> Result<u64> {
        let mut new_material = new_material.into();
        if new_material.is_empty() {
            return Err(SecretError::InvalidRegistration(
                "replacement secret material must not be empty".into(),
            ));
        }
        let record = self
            .secrets
            .get_mut(credential_ref)
            .ok_or_else(|| SecretError::UnknownCredential(credential_ref.into()))?;
        record.material.fill(0);
        std::mem::swap(&mut record.material, &mut new_material);
        new_material.fill(0);
        record.version = record
            .version
            .checked_add(1)
            .ok_or(SecretError::VersionExhausted)?;
        Ok(record.version)
    }

    pub fn prepare_use(
        &self,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        credential_ref: &str,
        consumer: &str,
        purpose: &str,
    ) -> Result<ActionRequest> {
        validate_identifier("consumer", consumer)?;
        if purpose.trim().is_empty() {
            return Err(SecretError::InvalidPurpose);
        }
        let record = self
            .secrets
            .get(credential_ref)
            .ok_or_else(|| SecretError::UnknownCredential(credential_ref.into()))?;
        if !record.allowed_consumers.contains(consumer) {
            return Err(SecretError::ConsumerNotAllowed {
                credential_ref: credential_ref.into(),
                consumer: consumer.into(),
            });
        }

        Ok(ActionRequest {
            request_id: request_id.into(),
            session_id: session_id.into(),
            operation: OPERATION.into(),
            resource: Resource {
                kind: RESOURCE_KIND.into(),
                value: resource_value(credential_ref, record.version),
            },
            arguments: json!({
                "credential_ref": credential_ref,
                "consumer": consumer,
                "secret_version": record.version,
                "purpose_sha256": sha256_text(purpose),
            }),
        })
    }

    pub fn execute_with<T>(
        &self,
        permit: ExecutionPermit,
        ledger: &mut AuditLedger,
        timestamp_unix_ms: i64,
        consume: impl FnOnce(&[u8]) -> T,
    ) -> Result<T> {
        permit
            .validate_at(timestamp_unix_ms)
            .map_err(|error| SecretError::InvalidPermit(error.to_string()))?;
        let request = permit.request();
        if request.operation != OPERATION || request.resource.kind != RESOURCE_KIND {
            return Err(SecretError::InvalidPermit(
                "permit is not for secret.use".into(),
            ));
        }

        let credential_ref = text_argument(&request.arguments, "credential_ref")?;
        let consumer = text_argument(&request.arguments, "consumer")?;
        let version = request
            .arguments
            .get("secret_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| SecretError::InvalidPermit("missing secret_version".into()))?;

        let record = self
            .secrets
            .get(credential_ref)
            .ok_or_else(|| SecretError::UnknownCredential(credential_ref.into()))?;
        if record.version != version {
            return Err(SecretError::SecretChangedAfterAuthorization {
                credential_ref: credential_ref.into(),
                authorized_version: version,
                current_version: record.version,
            });
        }
        if !record.allowed_consumers.contains(consumer) {
            return Err(SecretError::ConsumerNotAllowed {
                credential_ref: credential_ref.into(),
                consumer: consumer.into(),
            });
        }
        if request.resource.value != resource_value(credential_ref, version) {
            return Err(SecretError::InvalidPermit(
                "secret resource does not match credential reference and version".into(),
            ));
        }

        let (authority, grant_id) = permit_source(permit.source());
        ledger.append(AuditEntryInput {
            timestamp_unix_ms,
            event_type: AuditEventType::SecretUsed,
            session_id: Some(request.session_id.clone()),
            request_id: Some(request.request_id.clone()),
            operation: Some(request.operation.clone()),
            resource_kind: Some(request.resource.kind.clone()),
            resource_value: Some(request.resource.value.clone()),
            decision: None,
            policy_rule: permit.rule_id().map(str::to_string),
            reason: Some("credential material released only to the authorized consumer".into()),
            credential_ref: Some(credential_ref.into()),
            metadata: json!({
                "consumer": consumer,
                "secret_version": version,
                "authority": authority,
                "grant_id": grant_id,
                "request_fingerprint": permit.request_fingerprint(),
                "purpose_sha256": request.arguments.get("purpose_sha256"),
            }),
        })?;

        Ok(consume(&record.material))
    }
}

fn resource_value(credential_ref: &str, version: u64) -> String {
    format!("{credential_ref}#v{version}")
}

fn validate_identifier(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > 128
        || value.chars().any(|character| character.is_control())
    {
        return Err(SecretError::InvalidRegistration(format!(
            "{field} must be non-empty, at most 128 characters, and contain no control characters"
        )));
    }
    Ok(())
}

fn text_argument<'a>(arguments: &'a Value, key: &str) -> Result<&'a str> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| SecretError::InvalidPermit(format!("missing or invalid {key}")))
}

fn sha256_text(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn permit_source(source: &PermitSource) -> (&'static str, Option<&str>) {
    match source {
        PermitSource::Policy => ("POLICY", None),
        PermitSource::ApprovalOnce { grant_id } => ("APPROVAL_ONCE", Some(grant_id)),
        PermitSource::ApprovalSession { grant_id } => ("APPROVAL_SESSION", Some(grant_id)),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("invalid secret registration: {0}")]
    InvalidRegistration(String),
    #[error("duplicate credential reference: {0}")]
    DuplicateCredential(String),
    #[error("unknown credential reference: {0}")]
    UnknownCredential(String),
    #[error("consumer {consumer} is not allowed to use {credential_ref}")]
    ConsumerNotAllowed {
        credential_ref: String,
        consumer: String,
    },
    #[error("secret purpose must not be empty")]
    InvalidPurpose,
    #[error("secret version counter exhausted")]
    VersionExhausted,
    #[error("invalid secret permit: {0}")]
    InvalidPermit(String),
    #[error(
        "secret {credential_ref} changed after authorization: authorized v{authorized_version}, current v{current_version}"
    )]
    SecretChangedAfterAuthorization {
        credential_ref: String,
        authorized_version: u64,
        current_version: u64,
    },
    #[error("secret audit error: {0}")]
    Audit(#[from] AuditError),
}

pub type Result<T> = std::result::Result<T, SecretError>;

#[cfg(test)]
mod tests {
    use super::*;
    use latch_approvals::ApprovalStore;
    use latch_audit::AuditLedger;
    use latch_core::{evaluate, Effect, Policy, Rule, Session};

    fn session() -> Session {
        Session {
            id: "lat_secret".into(),
            principal: "local-user".into(),
            purpose: "test secret broker".into(),
            expires_at_unix: 10_000,
            revoked: false,
        }
    }

    fn broker() -> SecretBroker {
        SecretBroker::new([SecretRegistration::new(
            "github_main",
            b"super-secret-token".to_vec(),
            ["github-api"],
        )
        .unwrap()])
        .unwrap()
    }

    fn permit_for(broker: &SecretBroker, request_id: &str) -> ExecutionPermit {
        let request = broker
            .prepare_use(
                request_id,
                "lat_secret",
                "github_main",
                "github-api",
                "write repository file",
            )
            .unwrap();
        let policy = Policy {
            version: 1,
            rules: vec![Rule {
                id: "allow-secret-test".into(),
                effect: Effect::Allow,
                operation: OPERATION.into(),
                resource_kind: RESOURCE_KIND.into(),
                resource_prefix: "github_main#v1".into(),
            }],
        };
        let decision = evaluate(&session(), &policy, &request, 1);
        let mut approvals = ApprovalStore::in_memory().unwrap();
        approvals
            .authorize(&session(), &request, &decision, 1_000)
            .unwrap()
    }

    #[test]
    fn request_contains_reference_not_material() {
        let broker = broker();
        let request = broker
            .prepare_use(
                "req_1",
                "lat_secret",
                "github_main",
                "github-api",
                "write repository file",
            )
            .unwrap();
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(encoded.contains("github_main"));
        assert!(!encoded.contains("super-secret-token"));
    }

    #[test]
    fn material_is_exposed_only_inside_authorized_consumer() {
        let broker = broker();
        let permit = permit_for(&broker, "req_2");
        let mut ledger = AuditLedger::in_memory().unwrap();
        let length = broker
            .execute_with(permit, &mut ledger, 1_100, |material| {
                assert_eq!(material, b"super-secret-token");
                material.len()
            })
            .unwrap();
        assert_eq!(length, 18);
        assert!(ledger.verify_chain().unwrap().valid);
    }

    #[test]
    fn rotation_invalidates_stale_permit() {
        let mut broker = broker();
        let permit = permit_for(&broker, "req_3");
        broker
            .rotate("github_main", b"replacement".to_vec())
            .unwrap();
        let mut ledger = AuditLedger::in_memory().unwrap();
        assert!(matches!(
            broker.execute_with(permit, &mut ledger, 1_100, |_| ()),
            Err(SecretError::SecretChangedAfterAuthorization { .. })
        ));
    }

    #[test]
    fn consumer_scope_is_enforced_before_authorization() {
        let broker = broker();
        assert!(matches!(
            broker.prepare_use(
                "req_4",
                "lat_secret",
                "github_main",
                "untrusted-plugin",
                "read token",
            ),
            Err(SecretError::ConsumerNotAllowed { .. })
        ));
    }
}

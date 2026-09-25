use latch_core::{fingerprint, ActionRequest, Decision, Effect, Session};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    SessionCreated,
    SessionExpired,
    RequestReceived,
    PolicyAllow,
    PolicyDeny,
    ApprovalRequired,
    ApprovalGranted,
    ApprovalDenied,
    SecretUsed,
    ToolChanged,
    ToolForwarded,
    ToolResult,
    PolicyChanged,
}

impl AuditEventType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionCreated => "SESSION_CREATED",
            Self::SessionExpired => "SESSION_EXPIRED",
            Self::RequestReceived => "REQUEST_RECEIVED",
            Self::PolicyAllow => "POLICY_ALLOW",
            Self::PolicyDeny => "POLICY_DENY",
            Self::ApprovalRequired => "APPROVAL_REQUIRED",
            Self::ApprovalGranted => "APPROVAL_GRANTED",
            Self::ApprovalDenied => "APPROVAL_DENIED",
            Self::SecretUsed => "SECRET_USED",
            Self::ToolChanged => "TOOL_CHANGED",
            Self::ToolForwarded => "TOOL_FORWARDED",
            Self::ToolResult => "TOOL_RESULT",
            Self::PolicyChanged => "POLICY_CHANGED",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntryInput {
    pub timestamp_unix_ms: i64,
    pub event_type: AuditEventType,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub operation: Option<String>,
    pub resource_kind: Option<String>,
    pub resource_value: Option<String>,
    pub decision: Option<Effect>,
    pub policy_rule: Option<String>,
    pub reason: Option<String>,
    pub credential_ref: Option<String>,
    pub metadata: Value,
}

impl AuditEntryInput {
    pub fn new(timestamp_unix_ms: i64, event_type: AuditEventType) -> Self {
        Self {
            timestamp_unix_ms,
            event_type,
            session_id: None,
            request_id: None,
            operation: None,
            resource_kind: None,
            resource_value: None,
            decision: None,
            policy_rule: None,
            reason: None,
            credential_ref: None,
            metadata: Value::Null,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub sequence: i64,
    pub timestamp_unix_ms: i64,
    pub event_type: String,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub operation: Option<String>,
    pub resource_kind: Option<String>,
    pub resource_value: Option<String>,
    pub decision: Option<String>,
    pub policy_rule: Option<String>,
    pub reason: Option<String>,
    pub credential_ref: Option<String>,
    pub metadata_json: String,
    pub previous_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationFailure {
    pub sequence: i64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub valid: bool,
    pub entries_checked: usize,
    pub head_hash: String,
    pub failure: Option<VerificationFailure>,
}

#[derive(Debug)]
pub enum AuditError {
    Database(rusqlite::Error),
    DecisionFingerprintMismatch { expected: String, actual: String },
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "audit database error: {error}"),
            Self::DecisionFingerprintMismatch { expected, actual } => write!(
                f,
                "decision fingerprint does not match request: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::DecisionFingerprintMismatch { .. } => None,
        }
    }
}

impl From<rusqlite::Error> for AuditError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}

pub type Result<T> = std::result::Result<T, AuditError>;

pub struct AuditLedger {
    connection: Connection,
}

impl AuditLedger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path)?;
        let ledger = Self { connection };
        ledger.initialize()?;
        Ok(ledger)
    }

    pub fn in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        let ledger = Self { connection };
        ledger.initialize()?;
        Ok(ledger)
    }

    fn initialize(&self) -> Result<()> {
        self.connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;

            CREATE TABLE IF NOT EXISTS audit_entries (
                sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
                timestamp_unix_ms INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                session_id TEXT,
                request_id TEXT,
                operation TEXT,
                resource_kind TEXT,
                resource_value TEXT,
                decision TEXT,
                policy_rule TEXT,
                reason TEXT,
                credential_ref TEXT,
                metadata_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL CHECK(length(previous_hash) = 64),
                entry_hash TEXT NOT NULL UNIQUE CHECK(length(entry_hash) = 64)
            );

            CREATE TRIGGER IF NOT EXISTS audit_entries_no_update
            BEFORE UPDATE ON audit_entries
            BEGIN
                SELECT RAISE(ABORT, 'audit entries are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS audit_entries_no_delete
            BEFORE DELETE ON audit_entries
            BEGIN
                SELECT RAISE(ABORT, 'audit entries are immutable');
            END;
            ",
        )?;
        Ok(())
    }

    pub fn append(&mut self, input: AuditEntryInput) -> Result<AuditEntry> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let entry = append_in_transaction(&transaction, input)?;
        transaction.commit()?;
        Ok(entry)
    }

    pub fn record_authorization(
        &mut self,
        timestamp_unix_ms: i64,
        session: &Session,
        request: &ActionRequest,
        decision: &Decision,
    ) -> Result<(AuditEntry, AuditEntry)> {
        let expected_fingerprint = fingerprint(request);
        if decision.request_fingerprint != expected_fingerprint {
            return Err(AuditError::DecisionFingerprintMismatch {
                expected: expected_fingerprint,
                actual: decision.request_fingerprint.clone(),
            });
        }

        let arguments_sha256 = sha256_text(&canonical_json(&request.arguments));
        let request_metadata = serde_json::json!({
            "request_fingerprint": decision.request_fingerprint,
            "arguments_sha256": arguments_sha256,
        });
        let decision_metadata = serde_json::json!({
            "request_fingerprint": decision.request_fingerprint,
        });

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let request_entry = append_in_transaction(
            &transaction,
            AuditEntryInput {
                timestamp_unix_ms,
                event_type: AuditEventType::RequestReceived,
                session_id: Some(session.id.clone()),
                request_id: Some(request.request_id.clone()),
                operation: Some(request.operation.clone()),
                resource_kind: Some(request.resource.kind.clone()),
                resource_value: Some(request.resource.value.clone()),
                decision: None,
                policy_rule: None,
                reason: None,
                credential_ref: None,
                metadata: request_metadata,
            },
        )?;

        let decision_entry = append_in_transaction(
            &transaction,
            AuditEntryInput {
                timestamp_unix_ms,
                event_type: decision_event_type(decision.effect),
                session_id: Some(session.id.clone()),
                request_id: Some(request.request_id.clone()),
                operation: Some(request.operation.clone()),
                resource_kind: Some(request.resource.kind.clone()),
                resource_value: Some(request.resource.value.clone()),
                decision: Some(decision.effect),
                policy_rule: decision.rule_id.clone(),
                reason: Some(decision.reason.clone()),
                credential_ref: None,
                metadata: decision_metadata,
            },
        )?;

        transaction.commit()?;
        Ok((request_entry, decision_entry))
    }

    pub fn entries(&self) -> Result<Vec<AuditEntry>> {
        let mut statement = self.connection.prepare(
            "
            SELECT sequence, timestamp_unix_ms, event_type, session_id, request_id,
                   operation, resource_kind, resource_value, decision, policy_rule,
                   reason, credential_ref, metadata_json, previous_hash, entry_hash
            FROM audit_entries
            ORDER BY sequence ASC
            ",
        )?;

        let rows = statement.query_map([], row_to_entry)?;
        let entries = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    pub fn verify(&self) -> Result<VerificationReport> {
        let entries = self.entries()?;
        let mut previous_hash = GENESIS_HASH.to_string();
        for (index, entry) in entries.iter().enumerate() {
            let expected_sequence = index as i64 + 1;
            if entry.sequence != expected_sequence {
                return Ok(VerificationReport {
                    valid: false,
                    entries_checked: index,
                    head_hash: previous_hash,
                    failure: Some(VerificationFailure {
                        sequence: entry.sequence,
                        reason: format!(
                            "expected sequence {expected_sequence}, found {}",
                            entry.sequence
                        ),
                    }),
                });
            }

            if entry.previous_hash != previous_hash {
                return Ok(VerificationReport {
                    valid: false,
                    entries_checked: index,
                    head_hash: previous_hash,
                    failure: Some(VerificationFailure {
                        sequence: entry.sequence,
                        reason: "previous hash does not match verified chain head".into(),
                    }),
                });
            }

            let expected_hash = compute_entry_hash(entry);
            if entry.entry_hash != expected_hash {
                return Ok(VerificationReport {
                    valid: false,
                    entries_checked: index,
                    head_hash: previous_hash,
                    failure: Some(VerificationFailure {
                        sequence: entry.sequence,
                        reason: "entry hash does not match stored event content".into(),
                    }),
                });
            }

            previous_hash.clone_from(&entry.entry_hash);
        }

        Ok(VerificationReport {
            valid: true,
            entries_checked: entries.len(),
            head_hash: previous_hash,
            failure: None,
        })
    }
}

fn append_in_transaction(
    transaction: &Transaction<'_>,
    input: AuditEntryInput,
) -> Result<AuditEntry> {
    let last: Option<(i64, String)> = transaction
        .query_row(
            "SELECT sequence, entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let (sequence, previous_hash) = match last {
        Some((last_sequence, last_hash)) => (last_sequence + 1, last_hash),
        None => (1, GENESIS_HASH.to_string()),
    };

    let metadata_json = canonical_json(&input.metadata);
    let entry = AuditEntry {
        sequence,
        timestamp_unix_ms: input.timestamp_unix_ms,
        event_type: input.event_type.as_str().to_string(),
        session_id: input.session_id,
        request_id: input.request_id,
        operation: input.operation,
        resource_kind: input.resource_kind,
        resource_value: input.resource_value,
        decision: input.decision.map(effect_name).map(str::to_string),
        policy_rule: input.policy_rule,
        reason: input.reason,
        credential_ref: input.credential_ref,
        metadata_json,
        previous_hash,
        entry_hash: String::new(),
    };

    let mut entry = entry;
    entry.entry_hash = compute_entry_hash(&entry);

    transaction.execute(
        "
        INSERT INTO audit_entries (
            sequence, timestamp_unix_ms, event_type, session_id, request_id,
            operation, resource_kind, resource_value, decision, policy_rule,
            reason, credential_ref, metadata_json, previous_hash, entry_hash
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5,
            ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15
        )
        ",
        params![
            entry.sequence,
            entry.timestamp_unix_ms,
            entry.event_type,
            entry.session_id,
            entry.request_id,
            entry.operation,
            entry.resource_kind,
            entry.resource_value,
            entry.decision,
            entry.policy_rule,
            entry.reason,
            entry.credential_ref,
            entry.metadata_json,
            entry.previous_hash,
            entry.entry_hash,
        ],
    )?;

    Ok(entry)
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    Ok(AuditEntry {
        sequence: row.get(0)?,
        timestamp_unix_ms: row.get(1)?,
        event_type: row.get(2)?,
        session_id: row.get(3)?,
        request_id: row.get(4)?,
        operation: row.get(5)?,
        resource_kind: row.get(6)?,
        resource_value: row.get(7)?,
        decision: row.get(8)?,
        policy_rule: row.get(9)?,
        reason: row.get(10)?,
        credential_ref: row.get(11)?,
        metadata_json: row.get(12)?,
        previous_hash: row.get(13)?,
        entry_hash: row.get(14)?,
    })
}

fn decision_event_type(effect: Effect) -> AuditEventType {
    match effect {
        Effect::Allow => AuditEventType::PolicyAllow,
        Effect::Deny => AuditEventType::PolicyDeny,
        Effect::RequireApproval => AuditEventType::ApprovalRequired,
    }
}

const fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "ALLOW",
        Effect::Deny => "DENY",
        Effect::RequireApproval => "REQUIRE_APPROVAL",
    }
}

fn compute_entry_hash(entry: &AuditEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"latch-audit-v1\0");
    hash_i64(&mut hasher, entry.sequence);
    hash_i64(&mut hasher, entry.timestamp_unix_ms);
    hash_text(&mut hasher, &entry.event_type);
    hash_optional_text(&mut hasher, entry.session_id.as_deref());
    hash_optional_text(&mut hasher, entry.request_id.as_deref());
    hash_optional_text(&mut hasher, entry.operation.as_deref());
    hash_optional_text(&mut hasher, entry.resource_kind.as_deref());
    hash_optional_text(&mut hasher, entry.resource_value.as_deref());
    hash_optional_text(&mut hasher, entry.decision.as_deref());
    hash_optional_text(&mut hasher, entry.policy_rule.as_deref());
    hash_optional_text(&mut hasher, entry.reason.as_deref());
    hash_optional_text(&mut hasher, entry.credential_ref.as_deref());
    hash_text(&mut hasher, &entry.metadata_json);
    hash_text(&mut hasher, &entry.previous_hash);
    hex::encode(hasher.finalize())
}

fn hash_i64(hasher: &mut Sha256, value: i64) {
    hasher.update(value.to_be_bytes());
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hash_optional_text(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_text(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn sha256_text(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => {
            serde_json::to_string(value).expect("serializing a JSON string cannot fail")
        }
        Value::Array(values) => {
            let body = values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{body}]")
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let body = keys
                .into_iter()
                .map(|key| {
                    let encoded_key =
                        serde_json::to_string(key).expect("serializing a JSON key cannot fail");
                    format!("{encoded_key}:{}", canonical_json(&values[key]))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use latch_core::{evaluate, Policy, Resource, Rule};
    use serde_json::json;
    use tempfile::tempdir;

    fn session() -> Session {
        Session {
            id: "lat_84f29".into(),
            principal: "local-user".into(),
            purpose: "fix-tests".into(),
            expires_at_unix: 2_000,
            revoked: false,
        }
    }

    fn request(arguments: Value) -> ActionRequest {
        ActionRequest {
            request_id: "req_1".into(),
            session_id: "lat_84f29".into(),
            operation: "repository.write".into(),
            resource: Resource {
                kind: "repository".into(),
                value: "purysho/Witness".into(),
            },
            arguments,
        }
    }

    fn policy() -> Policy {
        Policy {
            version: 1,
            rules: vec![Rule {
                id: "review-write".into(),
                effect: Effect::RequireApproval,
                operation: "repository.write".into(),
                resource_kind: "repository".into(),
                resource_prefix: "purysho/Witness".into(),
            }],
        }
    }

    fn decision(request: &ActionRequest) -> Decision {
        evaluate(&session(), &policy(), request, 1_000)
    }

    #[test]
    fn persists_and_verifies_after_reopen() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("audit.sqlite");
        let request = request(json!({"path": "README.md"}));
        let decision = decision(&request);

        {
            let mut ledger = AuditLedger::open(&path)?;
            ledger.record_authorization(1_000_000, &session(), &request, &decision)?;
            let report = ledger.verify()?;
            assert!(report.valid);
            assert_eq!(report.entries_checked, 2);
        }

        let ledger = AuditLedger::open(&path)?;
        let entries = ledger.entries()?;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event_type, "REQUEST_RECEIVED");
        assert_eq!(entries[1].event_type, "APPROVAL_REQUIRED");
        assert!(ledger.verify()?.valid);
        Ok(())
    }

    #[test]
    fn authorization_records_request_and_decision_in_one_chain() -> Result<()> {
        let mut ledger = AuditLedger::in_memory()?;
        let request = request(json!({"path": "README.md"}));
        let decision = decision(&request);

        let (received, decided) =
            ledger.record_authorization(1_000_000, &session(), &request, &decision)?;

        assert_eq!(received.sequence, 1);
        assert_eq!(decided.sequence, 2);
        assert_eq!(decided.previous_hash, received.entry_hash);
        assert_eq!(received.request_id.as_deref(), Some("req_1"));
        assert_eq!(decided.policy_rule.as_deref(), Some("review-write"));
        assert_eq!(decided.decision.as_deref(), Some("REQUIRE_APPROVAL"));
        Ok(())
    }

    #[test]
    fn raw_request_arguments_are_not_persisted() -> Result<()> {
        let mut ledger = AuditLedger::in_memory()?;
        let request = request(json!({
            "path": "README.md",
            "token": "do-not-store-this-secret"
        }));
        let decision = decision(&request);

        ledger.record_authorization(1_000_000, &session(), &request, &decision)?;
        let serialized = ledger
            .entries()?
            .into_iter()
            .map(|entry| entry.metadata_json)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!serialized.contains("do-not-store-this-secret"));
        assert!(serialized.contains("arguments_sha256"));
        assert!(serialized.contains("request_fingerprint"));
        Ok(())
    }

    #[test]
    fn schema_blocks_update_and_delete() -> Result<()> {
        let mut ledger = AuditLedger::in_memory()?;
        ledger.append(AuditEntryInput::new(
            1_000_000,
            AuditEventType::SessionCreated,
        ))?;

        assert!(ledger
            .connection
            .execute(
                "UPDATE audit_entries SET event_type = 'POLICY_CHANGED' WHERE sequence = 1",
                []
            )
            .is_err());
        assert!(ledger
            .connection
            .execute("DELETE FROM audit_entries WHERE sequence = 1", [])
            .is_err());
        Ok(())
    }

    #[test]
    fn verification_detects_historical_tampering() -> Result<()> {
        let mut ledger = AuditLedger::in_memory()?;
        let request = request(json!({"path": "README.md"}));
        let decision = decision(&request);
        ledger.record_authorization(1_000_000, &session(), &request, &decision)?;

        ledger
            .connection
            .execute_batch("DROP TRIGGER audit_entries_no_update;")?;
        ledger.connection.execute(
            "UPDATE audit_entries SET reason = 'tampered' WHERE sequence = 2",
            [],
        )?;

        let report = ledger.verify()?;
        assert!(!report.valid);
        assert_eq!(
            report.failure.as_ref().map(|failure| failure.sequence),
            Some(2)
        );
        Ok(())
    }

    #[test]
    fn mismatched_decision_fingerprint_is_rejected() -> Result<()> {
        let mut ledger = AuditLedger::in_memory()?;
        let request = request(json!({"path": "README.md"}));
        let mut decision = decision(&request);
        decision.request_fingerprint = "incorrect".into();

        let error = ledger
            .record_authorization(1_000_000, &session(), &request, &decision)
            .expect_err("mismatched decision fingerprint must fail closed");

        assert!(matches!(
            error,
            AuditError::DecisionFingerprintMismatch { .. }
        ));
        assert!(ledger.entries()?.is_empty());
        Ok(())
    }
}

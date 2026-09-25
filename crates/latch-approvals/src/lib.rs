use latch_audit::{AuditEntryInput, AuditError, AuditEventType, AuditLedger};
use latch_core::{fingerprint, ActionRequest, Decision, Effect, Session};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermitSource {
    Policy,
    ApprovalOnce { grant_id: String },
    ApprovalSession { grant_id: String },
}

#[derive(Debug)]
pub struct ExecutionPermit {
    request: ActionRequest,
    rule_id: Option<String>,
    source: PermitSource,
    request_fingerprint: String,
    expires_at_unix_ms: i64,
}

impl ExecutionPermit {
    pub fn request(&self) -> &ActionRequest {
        &self.request
    }

    pub fn rule_id(&self) -> Option<&str> {
        self.rule_id.as_deref()
    }

    pub fn source(&self) -> &PermitSource {
        &self.source
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    pub const fn expires_at_unix_ms(&self) -> i64 {
        self.expires_at_unix_ms
    }

    pub fn validate_at(&self, now_unix_ms: i64) -> std::result::Result<(), PermitValidationError> {
        if now_unix_ms >= self.expires_at_unix_ms {
            Err(PermitValidationError::Expired {
                expires_at_unix_ms: self.expires_at_unix_ms,
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermitValidationError {
    Expired { expires_at_unix_ms: i64 },
}

impl fmt::Display for PermitValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired { expires_at_unix_ms } => {
                write!(
                    formatter,
                    "execution permit expired at {expires_at_unix_ms}"
                )
            }
        }
    }
}

impl std::error::Error for PermitValidationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    Once,
    Session,
}

impl ApprovalMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Once => "ONCE",
            Self::Session => "SESSION",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalResolution {
    Deny,
    AllowOnce,
    AllowSession { expires_at_unix_ms: Option<i64> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingStatus {
    Pending,
    Granted,
    Denied,
}

impl PendingStatus {
    fn from_str(value: &str) -> Option<Self> {
        match value {
            "PENDING" => Some(Self::Pending),
            "GRANTED" => Some(Self::Granted),
            "DENIED" => Some(Self::Denied),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    pub approval_id: String,
    pub request_id: String,
    pub session_id: String,
    pub request_fingerprint: String,
    pub scope_fingerprint: String,
    pub operation: String,
    pub resource_kind: String,
    pub resource_value: String,
    pub policy_rule: String,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub status: PendingStatus,
    pub resolved_at_unix_ms: Option<i64>,
    pub resolution: Option<String>,
    pub resolver_principal: Option<String>,
    pub grant_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantView {
    pub grant_id: String,
    pub approval_id: String,
    pub mode: ApprovalMode,
    pub session_id: String,
    pub request_fingerprint: String,
    pub scope_fingerprint: String,
    pub policy_rule: String,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub consumed_at_unix_ms: Option<i64>,
}

pub struct ApprovalStore {
    connection: Connection,
}

impl ApprovalStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let store = Self { connection };
        store.initialize()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let store = Self { connection };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<()> {
        self.connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;

            CREATE TABLE IF NOT EXISTS approval_requests (
                approval_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                request_fingerprint TEXT NOT NULL UNIQUE,
                scope_fingerprint TEXT NOT NULL,
                operation TEXT NOT NULL,
                resource_kind TEXT NOT NULL,
                resource_value TEXT NOT NULL,
                policy_rule TEXT NOT NULL,
                created_at_unix_ms INTEGER NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('PENDING', 'GRANTED', 'DENIED')),
                resolved_at_unix_ms INTEGER,
                resolution TEXT,
                resolver_principal TEXT,
                grant_id TEXT
            );

            CREATE INDEX IF NOT EXISTS approval_requests_pending_idx
            ON approval_requests(status, expires_at_unix_ms);

            CREATE TABLE IF NOT EXISTS approval_grants (
                grant_id TEXT PRIMARY KEY,
                approval_id TEXT NOT NULL,
                mode TEXT NOT NULL CHECK(mode IN ('ONCE', 'SESSION')),
                session_id TEXT NOT NULL,
                request_fingerprint TEXT NOT NULL,
                scope_fingerprint TEXT NOT NULL,
                policy_rule TEXT NOT NULL,
                operation TEXT NOT NULL,
                resource_kind TEXT NOT NULL,
                resource_value TEXT NOT NULL,
                created_at_unix_ms INTEGER NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL,
                consumed_at_unix_ms INTEGER,
                FOREIGN KEY(approval_id) REFERENCES approval_requests(approval_id)
            );

            CREATE INDEX IF NOT EXISTS approval_grants_once_idx
            ON approval_grants(session_id, policy_rule, request_fingerprint, mode, expires_at_unix_ms);

            CREATE INDEX IF NOT EXISTS approval_grants_session_idx
            ON approval_grants(session_id, policy_rule, scope_fingerprint, mode, expires_at_unix_ms);
            ",
        )?;
        Ok(())
    }

    pub fn submit(
        &mut self,
        session: &Session,
        request: &ActionRequest,
        decision: &Decision,
        now_unix_ms: i64,
    ) -> Result<PendingApproval> {
        validate_session_and_decision(session, request, decision, now_unix_ms)?;

        if decision.effect() != Effect::RequireApproval {
            return Err(ApprovalError::DecisionNotApproval(decision.effect()));
        }

        let policy_rule = decision
            .rule_id()
            .ok_or(ApprovalError::ApprovalDecisionMissingRule)?;
        let request_fingerprint = fingerprint(request);
        if let Some(existing) = self.pending_by_fingerprint(&request_fingerprint)? {
            return Ok(existing);
        }

        let scope_fingerprint = approval_scope_fingerprint(request);
        let expires_at_unix_ms = session_expiry_ms(session)?;
        let approval_id = stable_id(
            "apr",
            &[
                &request.request_id,
                &request_fingerprint,
                &now_unix_ms.to_string(),
            ],
        );

        self.connection.execute(
            "
            INSERT INTO approval_requests (
                approval_id, request_id, session_id, request_fingerprint, scope_fingerprint,
                operation, resource_kind, resource_value, policy_rule,
                created_at_unix_ms, expires_at_unix_ms, status
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'PENDING')
            ",
            params![
                approval_id,
                request.request_id,
                request.session_id,
                request_fingerprint,
                scope_fingerprint,
                request.operation,
                request.resource.kind,
                request.resource.value,
                policy_rule,
                now_unix_ms,
                expires_at_unix_ms,
            ],
        )?;

        self.get_pending(&approval_id)?
            .ok_or_else(|| ApprovalError::PendingNotFound(approval_id))
    }

    pub fn get_pending(&self, approval_id: &str) -> Result<Option<PendingApproval>> {
        self.connection
            .query_row(
                "
                SELECT approval_id, request_id, session_id, request_fingerprint, scope_fingerprint,
                       operation, resource_kind, resource_value, policy_rule,
                       created_at_unix_ms, expires_at_unix_ms, status,
                       resolved_at_unix_ms, resolution, resolver_principal, grant_id
                FROM approval_requests
                WHERE approval_id = ?1
                ",
                [approval_id],
                pending_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_pending(&self, now_unix_ms: i64) -> Result<Vec<PendingApproval>> {
        let mut statement = self.connection.prepare(
            "
            SELECT approval_id, request_id, session_id, request_fingerprint, scope_fingerprint,
                   operation, resource_kind, resource_value, policy_rule,
                   created_at_unix_ms, expires_at_unix_ms, status,
                   resolved_at_unix_ms, resolution, resolver_principal, grant_id
            FROM approval_requests
            WHERE status = 'PENDING' AND expires_at_unix_ms > ?1
            ORDER BY created_at_unix_ms ASC
            ",
        )?;
        let rows = statement.query_map([now_unix_ms], pending_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn list_active_grants(&self, now_unix_ms: i64) -> Result<Vec<GrantView>> {
        let mut statement = self.connection.prepare(
            "
            SELECT grant_id, approval_id, mode, session_id, request_fingerprint,
                   scope_fingerprint, policy_rule, created_at_unix_ms,
                   expires_at_unix_ms, consumed_at_unix_ms
            FROM approval_grants
            WHERE expires_at_unix_ms > ?1
              AND (mode = 'SESSION' OR consumed_at_unix_ms IS NULL)
            ORDER BY created_at_unix_ms ASC
            ",
        )?;
        let rows = statement.query_map([now_unix_ms], grant_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn resolve(
        &mut self,
        approval_id: &str,
        resolution: ApprovalResolution,
        resolver_principal: &str,
        now_unix_ms: i64,
        ledger: &mut AuditLedger,
    ) -> Result<Option<GrantView>> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let pending = transaction
            .query_row(
                "
                SELECT approval_id, request_id, session_id, request_fingerprint, scope_fingerprint,
                       operation, resource_kind, resource_value, policy_rule,
                       created_at_unix_ms, expires_at_unix_ms, status,
                       resolved_at_unix_ms, resolution, resolver_principal, grant_id
                FROM approval_requests
                WHERE approval_id = ?1
                ",
                [approval_id],
                pending_from_row,
            )
            .optional()?
            .ok_or_else(|| ApprovalError::PendingNotFound(approval_id.to_string()))?;

        if pending.status != PendingStatus::Pending {
            return Err(ApprovalError::PendingNotOpen {
                approval_id: approval_id.to_string(),
                status: pending.status,
            });
        }
        if now_unix_ms >= pending.expires_at_unix_ms {
            return Err(ApprovalError::PendingExpired {
                approval_id: approval_id.to_string(),
                expires_at_unix_ms: pending.expires_at_unix_ms,
            });
        }
        if resolver_principal.trim().is_empty() {
            return Err(ApprovalError::InvalidResolver);
        }

        match resolution {
            ApprovalResolution::Deny => {
                ledger.append(approval_audit_entry(
                    &pending,
                    now_unix_ms,
                    AuditEventType::ApprovalDenied,
                    Effect::Deny,
                    resolver_principal,
                    json!({
                        "approval_id": pending.approval_id,
                        "request_fingerprint": pending.request_fingerprint,
                        "resolution": "DENY",
                    }),
                ))?;

                transaction.execute(
                    "
                    UPDATE approval_requests
                    SET status = 'DENIED',
                        resolved_at_unix_ms = ?2,
                        resolution = 'DENY',
                        resolver_principal = ?3
                    WHERE approval_id = ?1 AND status = 'PENDING'
                    ",
                    params![approval_id, now_unix_ms, resolver_principal],
                )?;
                transaction.commit()?;
                Ok(None)
            }
            ApprovalResolution::AllowOnce => {
                let grant = insert_grant(
                    &transaction,
                    &pending,
                    ApprovalMode::Once,
                    pending.expires_at_unix_ms,
                    now_unix_ms,
                )?;

                ledger.append(approval_audit_entry(
                    &pending,
                    now_unix_ms,
                    AuditEventType::ApprovalGranted,
                    Effect::Allow,
                    resolver_principal,
                    json!({
                        "approval_id": pending.approval_id,
                        "grant_id": grant.grant_id,
                        "mode": "ONCE",
                        "expires_at_unix_ms": grant.expires_at_unix_ms,
                        "request_fingerprint": pending.request_fingerprint,
                    }),
                ))?;

                mark_granted(
                    &transaction,
                    approval_id,
                    resolver_principal,
                    now_unix_ms,
                    "ALLOW_ONCE",
                    &grant.grant_id,
                )?;
                transaction.commit()?;
                Ok(Some(grant))
            }
            ApprovalResolution::AllowSession { expires_at_unix_ms } => {
                let grant_expiry = match expires_at_unix_ms {
                    Some(expiry) if expiry <= now_unix_ms => {
                        return Err(ApprovalError::InvalidGrantExpiry(expiry))
                    }
                    Some(expiry) => expiry.min(pending.expires_at_unix_ms),
                    None => pending.expires_at_unix_ms,
                };

                let grant = insert_grant(
                    &transaction,
                    &pending,
                    ApprovalMode::Session,
                    grant_expiry,
                    now_unix_ms,
                )?;

                ledger.append(approval_audit_entry(
                    &pending,
                    now_unix_ms,
                    AuditEventType::ApprovalGranted,
                    Effect::Allow,
                    resolver_principal,
                    json!({
                        "approval_id": pending.approval_id,
                        "grant_id": grant.grant_id,
                        "mode": "SESSION",
                        "expires_at_unix_ms": grant.expires_at_unix_ms,
                        "scope_fingerprint": pending.scope_fingerprint,
                    }),
                ))?;

                mark_granted(
                    &transaction,
                    approval_id,
                    resolver_principal,
                    now_unix_ms,
                    "ALLOW_SESSION",
                    &grant.grant_id,
                )?;
                transaction.commit()?;
                Ok(Some(grant))
            }
        }
    }

    pub fn authorize(
        &mut self,
        session: &Session,
        request: &ActionRequest,
        decision: &Decision,
        now_unix_ms: i64,
    ) -> Result<ExecutionPermit> {
        validate_session_and_decision(session, request, decision, now_unix_ms)?;

        match decision.effect() {
            Effect::Deny => Err(ApprovalError::PolicyDenied),
            Effect::Allow => Ok(ExecutionPermit {
                request: request.clone(),
                rule_id: decision.rule_id().map(str::to_string),
                source: PermitSource::Policy,
                request_fingerprint: fingerprint(request),
                expires_at_unix_ms: session_expiry_ms(session)?,
            }),
            Effect::RequireApproval => {
                let policy_rule = decision
                    .rule_id()
                    .ok_or(ApprovalError::ApprovalDecisionMissingRule)?;
                let exact_fingerprint = fingerprint(request);
                let scope_fingerprint = approval_scope_fingerprint(request);
                let session_expiry = session_expiry_ms(session)?;

                let transaction = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;

                let once = transaction
                    .query_row(
                        "
                        SELECT grant_id, approval_id, mode, session_id, request_fingerprint,
                               scope_fingerprint, policy_rule, created_at_unix_ms,
                               expires_at_unix_ms, consumed_at_unix_ms
                        FROM approval_grants
                        WHERE mode = 'ONCE'
                          AND session_id = ?1
                          AND policy_rule = ?2
                          AND request_fingerprint = ?3
                          AND consumed_at_unix_ms IS NULL
                          AND expires_at_unix_ms > ?4
                        ORDER BY created_at_unix_ms ASC
                        LIMIT 1
                        ",
                        params![
                            request.session_id,
                            policy_rule,
                            exact_fingerprint,
                            now_unix_ms
                        ],
                        grant_from_row,
                    )
                    .optional()?;

                if let Some(grant) = once {
                    let changed = transaction.execute(
                        "
                        UPDATE approval_grants
                        SET consumed_at_unix_ms = ?2
                        WHERE grant_id = ?1
                          AND consumed_at_unix_ms IS NULL
                          AND expires_at_unix_ms > ?2
                        ",
                        params![grant.grant_id, now_unix_ms],
                    )?;
                    if changed != 1 {
                        return Err(ApprovalError::NoMatchingGrant);
                    }

                    transaction.commit()?;
                    return Ok(ExecutionPermit {
                        request: request.clone(),
                        rule_id: decision.rule_id().map(str::to_string),
                        source: PermitSource::ApprovalOnce {
                            grant_id: grant.grant_id,
                        },
                        request_fingerprint: exact_fingerprint,
                        expires_at_unix_ms: grant.expires_at_unix_ms.min(session_expiry),
                    });
                }

                let session_grant = transaction
                    .query_row(
                        "
                        SELECT grant_id, approval_id, mode, session_id, request_fingerprint,
                               scope_fingerprint, policy_rule, created_at_unix_ms,
                               expires_at_unix_ms, consumed_at_unix_ms
                        FROM approval_grants
                        WHERE mode = 'SESSION'
                          AND session_id = ?1
                          AND policy_rule = ?2
                          AND scope_fingerprint = ?3
                          AND expires_at_unix_ms > ?4
                        ORDER BY created_at_unix_ms DESC
                        LIMIT 1
                        ",
                        params![
                            request.session_id,
                            policy_rule,
                            scope_fingerprint,
                            now_unix_ms
                        ],
                        grant_from_row,
                    )
                    .optional()?;

                match session_grant {
                    Some(grant) => {
                        transaction.commit()?;
                        Ok(ExecutionPermit {
                            request: request.clone(),
                            rule_id: decision.rule_id().map(str::to_string),
                            source: PermitSource::ApprovalSession {
                                grant_id: grant.grant_id,
                            },
                            request_fingerprint: exact_fingerprint,
                            expires_at_unix_ms: grant.expires_at_unix_ms.min(session_expiry),
                        })
                    }
                    None => Err(ApprovalError::NoMatchingGrant),
                }
            }
        }
    }

    fn pending_by_fingerprint(&self, request_fingerprint: &str) -> Result<Option<PendingApproval>> {
        self.connection
            .query_row(
                "
                SELECT approval_id, request_id, session_id, request_fingerprint, scope_fingerprint,
                       operation, resource_kind, resource_value, policy_rule,
                       created_at_unix_ms, expires_at_unix_ms, status,
                       resolved_at_unix_ms, resolution, resolver_principal, grant_id
                FROM approval_requests
                WHERE request_fingerprint = ?1
                ",
                [request_fingerprint],
                pending_from_row,
            )
            .optional()
            .map_err(Into::into)
    }
}

fn validate_session_and_decision(
    session: &Session,
    request: &ActionRequest,
    decision: &Decision,
    now_unix_ms: i64,
) -> Result<()> {
    if request.session_id != session.id {
        return Err(ApprovalError::SessionMismatch);
    }
    if session.revoked {
        return Err(ApprovalError::SessionRevoked);
    }
    let session_expiry = session_expiry_ms(session)?;
    if now_unix_ms >= session_expiry {
        return Err(ApprovalError::SessionExpired {
            expires_at_unix_ms: session_expiry,
        });
    }

    let expected = fingerprint(request);
    if decision.request_fingerprint() != expected {
        return Err(ApprovalError::DecisionFingerprintMismatch {
            expected,
            actual: decision.request_fingerprint().to_string(),
        });
    }
    Ok(())
}

fn session_expiry_ms(session: &Session) -> Result<i64> {
    let seconds =
        i64::try_from(session.expires_at_unix).map_err(|_| ApprovalError::InvalidSessionExpiry)?;
    seconds
        .checked_mul(1_000)
        .ok_or(ApprovalError::InvalidSessionExpiry)
}

fn approval_scope_fingerprint(request: &ActionRequest) -> String {
    let mut scoped = request.clone();
    scoped.request_id.clear();
    fingerprint(&scoped)
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"latch-approval-id-v1");
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hex::encode(hasher.finalize());
    format!("{prefix}_{}", &digest[..20])
}

fn insert_grant(
    transaction: &rusqlite::Transaction<'_>,
    pending: &PendingApproval,
    mode: ApprovalMode,
    expires_at_unix_ms: i64,
    now_unix_ms: i64,
) -> Result<GrantView> {
    let grant_id = stable_id(
        "grt",
        &[
            &pending.approval_id,
            mode.as_str(),
            &now_unix_ms.to_string(),
            &expires_at_unix_ms.to_string(),
        ],
    );

    transaction.execute(
        "
        INSERT INTO approval_grants (
            grant_id, approval_id, mode, session_id, request_fingerprint,
            scope_fingerprint, policy_rule, operation, resource_kind, resource_value,
            created_at_unix_ms, expires_at_unix_ms, consumed_at_unix_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL)
        ",
        params![
            grant_id,
            pending.approval_id,
            mode.as_str(),
            pending.session_id,
            pending.request_fingerprint,
            pending.scope_fingerprint,
            pending.policy_rule,
            pending.operation,
            pending.resource_kind,
            pending.resource_value,
            now_unix_ms,
            expires_at_unix_ms,
        ],
    )?;

    Ok(GrantView {
        grant_id,
        approval_id: pending.approval_id.clone(),
        mode,
        session_id: pending.session_id.clone(),
        request_fingerprint: pending.request_fingerprint.clone(),
        scope_fingerprint: pending.scope_fingerprint.clone(),
        policy_rule: pending.policy_rule.clone(),
        created_at_unix_ms: now_unix_ms,
        expires_at_unix_ms,
        consumed_at_unix_ms: None,
    })
}

fn mark_granted(
    transaction: &rusqlite::Transaction<'_>,
    approval_id: &str,
    resolver_principal: &str,
    now_unix_ms: i64,
    resolution: &str,
    grant_id: &str,
) -> Result<()> {
    let changed = transaction.execute(
        "
        UPDATE approval_requests
        SET status = 'GRANTED',
            resolved_at_unix_ms = ?2,
            resolution = ?3,
            resolver_principal = ?4,
            grant_id = ?5
        WHERE approval_id = ?1 AND status = 'PENDING'
        ",
        params![
            approval_id,
            now_unix_ms,
            resolution,
            resolver_principal,
            grant_id
        ],
    )?;
    if changed != 1 {
        return Err(ApprovalError::PendingNotOpen {
            approval_id: approval_id.to_string(),
            status: PendingStatus::Granted,
        });
    }
    Ok(())
}

fn pending_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingApproval> {
    let status: String = row.get(11)?;
    Ok(PendingApproval {
        approval_id: row.get(0)?,
        request_id: row.get(1)?,
        session_id: row.get(2)?,
        request_fingerprint: row.get(3)?,
        scope_fingerprint: row.get(4)?,
        operation: row.get(5)?,
        resource_kind: row.get(6)?,
        resource_value: row.get(7)?,
        policy_rule: row.get(8)?,
        created_at_unix_ms: row.get(9)?,
        expires_at_unix_ms: row.get(10)?,
        status: PendingStatus::from_str(&status).ok_or_else(|| {
            rusqlite::Error::InvalidColumnType(11, "status".into(), rusqlite::types::Type::Text)
        })?,
        resolved_at_unix_ms: row.get(12)?,
        resolution: row.get(13)?,
        resolver_principal: row.get(14)?,
        grant_id: row.get(15)?,
    })
}

fn grant_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GrantView> {
    let mode: String = row.get(2)?;
    let mode = match mode.as_str() {
        "ONCE" => ApprovalMode::Once,
        "SESSION" => ApprovalMode::Session,
        _ => {
            return Err(rusqlite::Error::InvalidColumnType(
                2,
                "mode".into(),
                rusqlite::types::Type::Text,
            ))
        }
    };

    Ok(GrantView {
        grant_id: row.get(0)?,
        approval_id: row.get(1)?,
        mode,
        session_id: row.get(3)?,
        request_fingerprint: row.get(4)?,
        scope_fingerprint: row.get(5)?,
        policy_rule: row.get(6)?,
        created_at_unix_ms: row.get(7)?,
        expires_at_unix_ms: row.get(8)?,
        consumed_at_unix_ms: row.get(9)?,
    })
}

fn approval_audit_entry(
    pending: &PendingApproval,
    timestamp_unix_ms: i64,
    event_type: AuditEventType,
    effect: Effect,
    resolver_principal: &str,
    metadata: serde_json::Value,
) -> AuditEntryInput {
    AuditEntryInput {
        timestamp_unix_ms,
        event_type,
        session_id: Some(pending.session_id.clone()),
        request_id: Some(pending.request_id.clone()),
        operation: Some(pending.operation.clone()),
        resource_kind: Some(pending.resource_kind.clone()),
        resource_value: Some(pending.resource_value.clone()),
        decision: Some(effect),
        policy_rule: Some(pending.policy_rule.clone()),
        reason: Some(format!("resolved by {resolver_principal}")),
        credential_ref: None,
        metadata,
    }
}

#[derive(Debug)]
pub enum ApprovalError {
    Database(rusqlite::Error),
    Audit(AuditError),
    DecisionFingerprintMismatch {
        expected: String,
        actual: String,
    },
    DecisionNotApproval(Effect),
    ApprovalDecisionMissingRule,
    SessionMismatch,
    SessionRevoked,
    SessionExpired {
        expires_at_unix_ms: i64,
    },
    InvalidSessionExpiry,
    PendingNotFound(String),
    PendingNotOpen {
        approval_id: String,
        status: PendingStatus,
    },
    PendingExpired {
        approval_id: String,
        expires_at_unix_ms: i64,
    },
    InvalidGrantExpiry(i64),
    InvalidResolver,
    PolicyDenied,
    NoMatchingGrant,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "approval database error: {error}"),
            Self::Audit(error) => write!(formatter, "approval audit error: {error}"),
            Self::DecisionFingerprintMismatch { expected, actual } => write!(
                formatter,
                "decision fingerprint does not match request: expected {expected}, got {actual}"
            ),
            Self::DecisionNotApproval(effect) => {
                write!(formatter, "decision is not approval-required: {effect:?}")
            }
            Self::ApprovalDecisionMissingRule => {
                write!(formatter, "approval-required decision has no policy rule")
            }
            Self::SessionMismatch => write!(formatter, "request session does not match session"),
            Self::SessionRevoked => write!(formatter, "session is revoked"),
            Self::SessionExpired { expires_at_unix_ms } => {
                write!(formatter, "session expired at {expires_at_unix_ms}")
            }
            Self::InvalidSessionExpiry => write!(formatter, "session expiry cannot be represented"),
            Self::PendingNotFound(id) => write!(formatter, "approval request not found: {id}"),
            Self::PendingNotOpen {
                approval_id,
                status,
            } => write!(
                formatter,
                "approval request {approval_id} is not pending: {status:?}"
            ),
            Self::PendingExpired {
                approval_id,
                expires_at_unix_ms,
            } => write!(
                formatter,
                "approval request {approval_id} expired at {expires_at_unix_ms}"
            ),
            Self::InvalidGrantExpiry(expiry) => {
                write!(formatter, "grant expiry must be in the future: {expiry}")
            }
            Self::InvalidResolver => write!(formatter, "resolver principal cannot be empty"),
            Self::PolicyDenied => write!(formatter, "policy denied the request"),
            Self::NoMatchingGrant => {
                write!(formatter, "no live approval grant matches the request")
            }
        }
    }
}

impl std::error::Error for ApprovalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Audit(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for ApprovalError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}

impl From<AuditError> for ApprovalError {
    fn from(value: AuditError) -> Self {
        Self::Audit(value)
    }
}

pub type Result<T> = std::result::Result<T, ApprovalError>;

#[cfg(test)]
mod tests {
    use super::*;
    use latch_core::{evaluate, Policy, Resource, Rule};
    use serde_json::json;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::tempdir;

    fn session(id: &str) -> Session {
        Session {
            id: id.into(),
            principal: "local-user".into(),
            purpose: "approval-test".into(),
            expires_at_unix: 10_000,
            revoked: false,
        }
    }

    fn request(
        id: &str,
        session_id: &str,
        value: &str,
        arguments: serde_json::Value,
    ) -> ActionRequest {
        ActionRequest {
            request_id: id.into(),
            session_id: session_id.into(),
            operation: "repository.delete".into(),
            resource: Resource {
                kind: "repository".into(),
                value: value.into(),
            },
            arguments,
        }
    }

    fn approval_policy() -> Policy {
        Policy {
            version: 1,
            rules: vec![Rule {
                id: "review-delete".into(),
                effect: Effect::RequireApproval,
                operation: "repository.delete".into(),
                resource_kind: "repository".into(),
                resource_prefix: "purysho/Witness".into(),
            }],
        }
    }

    fn allow_policy() -> Policy {
        Policy {
            version: 1,
            rules: vec![Rule {
                id: "allow-delete".into(),
                effect: Effect::Allow,
                operation: "repository.delete".into(),
                resource_kind: "repository".into(),
                resource_prefix: "purysho/Witness".into(),
            }],
        }
    }

    #[test]
    fn direct_allow_mints_policy_permit() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let session = session("lat_a");
        let request = request("req_a", "lat_a", "purysho/Witness", json!({"branch":"old"}));
        let decision = evaluate(&session, &allow_policy(), &request, 1);
        let mut store = ApprovalStore::in_memory()?;

        let permit = store.authorize(&session, &request, &decision, 1_000)?;

        assert!(matches!(permit.source(), PermitSource::Policy));
        assert_eq!(permit.request_fingerprint(), fingerprint(&request));
        Ok(())
    }

    #[test]
    fn allow_once_is_exact_and_consumed_atomically(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let session = session("lat_once");
        let request = request(
            "req_once",
            "lat_once",
            "purysho/Witness",
            json!({"branch":"experiment-old"}),
        );
        let decision = evaluate(&session, &approval_policy(), &request, 1);
        let mut store = ApprovalStore::in_memory()?;
        let mut ledger = AuditLedger::in_memory()?;
        let pending = store.submit(&session, &request, &decision, 1_000)?;
        store.resolve(
            &pending.approval_id,
            ApprovalResolution::AllowOnce,
            "local-user",
            1_100,
            &mut ledger,
        )?;

        let permit = store.authorize(&session, &request, &decision, 1_200)?;
        assert!(matches!(permit.source(), PermitSource::ApprovalOnce { .. }));

        assert!(matches!(
            store.authorize(&session, &request, &decision, 1_300),
            Err(ApprovalError::NoMatchingGrant)
        ));
        Ok(())
    }

    #[test]
    fn changed_material_field_invalidates_once_approval(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let session = session("lat_mutation");
        let original = request(
            "req_original",
            "lat_mutation",
            "purysho/Witness",
            json!({"branch":"old"}),
        );
        let original_decision = evaluate(&session, &approval_policy(), &original, 1);
        let mut store = ApprovalStore::in_memory()?;
        let mut ledger = AuditLedger::in_memory()?;
        let pending = store.submit(&session, &original, &original_decision, 1_000)?;
        store.resolve(
            &pending.approval_id,
            ApprovalResolution::AllowOnce,
            "local-user",
            1_100,
            &mut ledger,
        )?;

        let changed = request(
            "req_changed",
            "lat_mutation",
            "purysho/Witness",
            json!({"branch":"different"}),
        );
        let changed_decision = evaluate(&session, &approval_policy(), &changed, 1);

        assert!(matches!(
            store.authorize(&session, &changed, &changed_decision, 1_200),
            Err(ApprovalError::NoMatchingGrant)
        ));

        assert!(store
            .authorize(&session, &original, &original_decision, 1_300)
            .is_ok());
        Ok(())
    }

    #[test]
    fn session_grant_allows_only_same_capability_shape(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let session = session("lat_session");
        let original = request(
            "req_1",
            "lat_session",
            "purysho/Witness",
            json!({"branch":"old"}),
        );
        let original_decision = evaluate(&session, &approval_policy(), &original, 1);
        let mut store = ApprovalStore::in_memory()?;
        let mut ledger = AuditLedger::in_memory()?;
        let pending = store.submit(&session, &original, &original_decision, 1_000)?;
        store.resolve(
            &pending.approval_id,
            ApprovalResolution::AllowSession {
                expires_at_unix_ms: Some(5_000),
            },
            "local-user",
            1_100,
            &mut ledger,
        )?;

        let repeated = request(
            "req_2",
            "lat_session",
            "purysho/Witness",
            json!({"branch":"old"}),
        );
        let repeated_decision = evaluate(&session, &approval_policy(), &repeated, 1);
        let permit = store.authorize(&session, &repeated, &repeated_decision, 1_200)?;
        assert!(matches!(
            permit.source(),
            PermitSource::ApprovalSession { .. }
        ));

        let changed = request(
            "req_3",
            "lat_session",
            "purysho/Witness",
            json!({"branch":"different"}),
        );
        let changed_decision = evaluate(&session, &approval_policy(), &changed, 1);
        assert!(matches!(
            store.authorize(&session, &changed, &changed_decision, 1_300),
            Err(ApprovalError::NoMatchingGrant)
        ));
        Ok(())
    }

    #[test]
    fn session_grant_does_not_cross_sessions() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let first_session = session("lat_first");
        let original = request(
            "req_1",
            "lat_first",
            "purysho/Witness",
            json!({"branch":"old"}),
        );
        let decision = evaluate(&first_session, &approval_policy(), &original, 1);
        let mut store = ApprovalStore::in_memory()?;
        let mut ledger = AuditLedger::in_memory()?;
        let pending = store.submit(&first_session, &original, &decision, 1_000)?;
        store.resolve(
            &pending.approval_id,
            ApprovalResolution::AllowSession {
                expires_at_unix_ms: None,
            },
            "local-user",
            1_100,
            &mut ledger,
        )?;

        let second_session = session("lat_second");
        let other = request(
            "req_2",
            "lat_second",
            "purysho/Witness",
            json!({"branch":"old"}),
        );
        let other_decision = evaluate(&second_session, &approval_policy(), &other, 1);

        assert!(matches!(
            store.authorize(&second_session, &other, &other_decision, 1_200),
            Err(ApprovalError::NoMatchingGrant)
        ));
        Ok(())
    }

    #[test]
    fn expired_grant_provides_no_authority() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let session = session("lat_expiry");
        let request = request(
            "req_expiry",
            "lat_expiry",
            "purysho/Witness",
            json!({"branch":"old"}),
        );
        let decision = evaluate(&session, &approval_policy(), &request, 1);
        let mut store = ApprovalStore::in_memory()?;
        let mut ledger = AuditLedger::in_memory()?;
        let pending = store.submit(&session, &request, &decision, 1_000)?;
        store.resolve(
            &pending.approval_id,
            ApprovalResolution::AllowSession {
                expires_at_unix_ms: Some(1_500),
            },
            "local-user",
            1_100,
            &mut ledger,
        )?;

        assert!(matches!(
            store.authorize(&session, &request, &decision, 1_500),
            Err(ApprovalError::NoMatchingGrant)
        ));
        Ok(())
    }

    #[test]
    fn denied_request_cannot_be_approved_later(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let session = session("lat_deny");
        let request = request(
            "req_deny",
            "lat_deny",
            "purysho/Witness",
            json!({"branch":"old"}),
        );
        let decision = evaluate(&session, &approval_policy(), &request, 1);
        let mut store = ApprovalStore::in_memory()?;
        let mut ledger = AuditLedger::in_memory()?;
        let pending = store.submit(&session, &request, &decision, 1_000)?;
        store.resolve(
            &pending.approval_id,
            ApprovalResolution::Deny,
            "local-user",
            1_100,
            &mut ledger,
        )?;

        assert!(matches!(
            store.authorize(&session, &request, &decision, 1_200),
            Err(ApprovalError::NoMatchingGrant)
        ));
        assert!(matches!(
            store.resolve(
                &pending.approval_id,
                ApprovalResolution::AllowOnce,
                "local-user",
                1_300,
                &mut ledger
            ),
            Err(ApprovalError::PendingNotOpen { .. })
        ));
        Ok(())
    }

    #[test]
    fn later_policy_deny_overrides_existing_grant(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let session = session("lat_policy");
        let request = request(
            "req_policy",
            "lat_policy",
            "purysho/Witness",
            json!({"branch":"old"}),
        );
        let approval_decision = evaluate(&session, &approval_policy(), &request, 1);
        let mut store = ApprovalStore::in_memory()?;
        let mut ledger = AuditLedger::in_memory()?;
        let pending = store.submit(&session, &request, &approval_decision, 1_000)?;
        store.resolve(
            &pending.approval_id,
            ApprovalResolution::AllowSession {
                expires_at_unix_ms: None,
            },
            "local-user",
            1_100,
            &mut ledger,
        )?;

        let deny_policy = Policy {
            version: 2,
            rules: vec![Rule {
                id: "deny-delete".into(),
                effect: Effect::Deny,
                operation: "repository.delete".into(),
                resource_kind: "repository".into(),
                resource_prefix: "purysho/Witness".into(),
            }],
        };
        let deny_decision = evaluate(&session, &deny_policy, &request, 1);

        assert!(matches!(
            store.authorize(&session, &request, &deny_decision, 1_200),
            Err(ApprovalError::PolicyDenied)
        ));
        Ok(())
    }

    #[test]
    fn session_expiry_caps_permit_and_grant_authority(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut short_session = session("lat_short");
        short_session.expires_at_unix = 2;
        let request = request(
            "req_short",
            "lat_short",
            "purysho/Witness",
            json!({"branch":"old"}),
        );
        let decision = evaluate(&short_session, &approval_policy(), &request, 1);
        let mut store = ApprovalStore::in_memory()?;
        let mut ledger = AuditLedger::in_memory()?;
        let pending = store.submit(&short_session, &request, &decision, 1_000)?;
        let grant = store
            .resolve(
                &pending.approval_id,
                ApprovalResolution::AllowSession {
                    expires_at_unix_ms: Some(9_000),
                },
                "local-user",
                1_100,
                &mut ledger,
            )?
            .expect("grant");

        assert_eq!(grant.expires_at_unix_ms, 2_000);
        let permit = store.authorize(&short_session, &request, &decision, 1_200)?;
        assert_eq!(permit.expires_at_unix_ms(), 2_000);
        assert!(permit.validate_at(1_999).is_ok());
        assert!(permit.validate_at(2_000).is_err());
        Ok(())
    }

    #[test]
    fn approval_resolution_is_audited_without_request_arguments(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let session = session("lat_audit");
        let request = request(
            "req_audit",
            "lat_audit",
            "purysho/Witness",
            json!({"branch":"secret-branch-value"}),
        );
        let decision = evaluate(&session, &approval_policy(), &request, 1);
        let mut store = ApprovalStore::in_memory()?;
        let mut ledger = AuditLedger::in_memory()?;
        let pending = store.submit(&session, &request, &decision, 1_000)?;
        store.resolve(
            &pending.approval_id,
            ApprovalResolution::AllowOnce,
            "local-user",
            1_100,
            &mut ledger,
        )?;

        let entries = ledger.entries()?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "APPROVAL_GRANTED");
        assert!(!entries[0].metadata_json.contains("secret-branch-value"));
        assert!(ledger.verify()?.valid);
        Ok(())
    }

    #[test]
    fn pending_and_grants_survive_reopen() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("approvals.sqlite");
        let session = session("lat_persist");
        let request = request(
            "req_persist",
            "lat_persist",
            "purysho/Witness",
            json!({"branch":"old"}),
        );
        let decision = evaluate(&session, &approval_policy(), &request, 1);
        let mut ledger = AuditLedger::in_memory()?;

        let approval_id = {
            let mut store = ApprovalStore::open(&path)?;
            let pending = store.submit(&session, &request, &decision, 1_000)?;
            store.resolve(
                &pending.approval_id,
                ApprovalResolution::AllowSession {
                    expires_at_unix_ms: None,
                },
                "local-user",
                1_100,
                &mut ledger,
            )?;
            pending.approval_id
        };

        let store = ApprovalStore::open(&path)?;
        let pending = store
            .get_pending(&approval_id)?
            .expect("persisted approval");
        assert_eq!(pending.status, PendingStatus::Granted);
        assert_eq!(store.list_active_grants(1_200)?.len(), 1);
        Ok(())
    }

    #[test]
    fn concurrent_allow_once_can_be_consumed_only_once(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("approvals.sqlite");
        let session = session("lat_race");
        let request = request(
            "req_race",
            "lat_race",
            "purysho/Witness",
            json!({"branch":"old"}),
        );
        let decision = evaluate(&session, &approval_policy(), &request, 1);
        let mut ledger = AuditLedger::in_memory()?;

        {
            let mut store = ApprovalStore::open(&path)?;
            let pending = store.submit(&session, &request, &decision, 1_000)?;
            store.resolve(
                &pending.approval_id,
                ApprovalResolution::AllowOnce,
                "local-user",
                1_100,
                &mut ledger,
            )?;
        }

        let barrier = Arc::new(Barrier::new(2));
        let handles = (0..2)
            .map(|_| {
                let path = path.clone();
                let session = session.clone();
                let request = request.clone();
                let decision = decision.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let mut store = ApprovalStore::open(path).expect("open store");
                    barrier.wait();
                    store
                        .authorize(&session, &request, &decision, 1_200)
                        .is_ok()
                })
            })
            .collect::<Vec<_>>();

        let successes = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .filter(|success| *success)
            .count();

        assert_eq!(successes, 1);
        Ok(())
    }
}

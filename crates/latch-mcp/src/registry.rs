use crate::{
    descriptor_fingerprint, schema_fingerprint, tool_identity_fingerprint,
    validate_tool_descriptor, DiscoverySnapshot, ProviderIdentity, SchemaError, ToolDescriptor,
    MCP_PROTOCOL_REVISION,
};
use latch_audit::{AuditEntryInput, AuditError, AuditEventType, AuditLedger};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::json;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

pub const MAX_DISCOVERED_TOOLS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolState {
    Active,
    Changed,
    Missing,
}

impl ToolState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Changed => "CHANGED",
            Self::Missing => "MISSING",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "ACTIVE" => Some(Self::Active),
            "CHANGED" => Some(Self::Changed),
            "MISSING" => Some(Self::Missing),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolRecord {
    pub provider_id: String,
    pub tool_name: String,
    pub state: ToolState,
    pub trusted_schema_fingerprint: String,
    pub trusted_descriptor_fingerprint: String,
    pub trusted_identity_fingerprint: String,
    pub observed_schema_fingerprint: String,
    pub observed_descriptor_fingerprint: String,
    pub observed_identity_fingerprint: String,
    pub trusted_descriptor: ToolDescriptor,
    pub observed_descriptor: ToolDescriptor,
    pub first_seen_unix_ms: i64,
    pub last_seen_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiscoveryReport {
    pub added: usize,
    pub unchanged: usize,
    pub changed: usize,
    pub missing: usize,
}

pub struct ToolRegistry {
    connection: Connection,
}

impl ToolRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let registry = Self { connection };
        registry.initialize()?;
        Ok(registry)
    }

    pub fn in_memory() -> Result<Self, RegistryError> {
        let connection = Connection::open_in_memory()?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let registry = Self { connection };
        registry.initialize()?;
        Ok(registry)
    }

    fn initialize(&self) -> Result<(), RegistryError> {
        self.connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;

            CREATE TABLE IF NOT EXISTS mcp_providers (
                provider_id TEXT PRIMARY KEY,
                provider_fingerprint TEXT NOT NULL,
                transport_kind TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                registered_at_unix_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mcp_tools (
                provider_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('ACTIVE', 'CHANGED', 'MISSING')),
                trusted_schema_fingerprint TEXT NOT NULL,
                trusted_descriptor_fingerprint TEXT NOT NULL,
                trusted_identity_fingerprint TEXT NOT NULL,
                observed_schema_fingerprint TEXT NOT NULL,
                observed_descriptor_fingerprint TEXT NOT NULL,
                observed_identity_fingerprint TEXT NOT NULL,
                trusted_descriptor_json TEXT NOT NULL,
                observed_descriptor_json TEXT NOT NULL,
                first_seen_unix_ms INTEGER NOT NULL,
                last_seen_unix_ms INTEGER NOT NULL,
                PRIMARY KEY(provider_id, tool_name),
                FOREIGN KEY(provider_id) REFERENCES mcp_providers(provider_id)
            );

            CREATE INDEX IF NOT EXISTS mcp_tools_state_idx
            ON mcp_tools(provider_id, state);
            ",
        )?;
        Ok(())
    }

    pub fn register_provider(
        &mut self,
        provider: &ProviderIdentity,
        now_unix_ms: i64,
    ) -> Result<(), RegistryError> {
        let existing: Option<String> = self
            .connection
            .query_row(
                "SELECT provider_fingerprint FROM mcp_providers WHERE provider_id = ?1",
                [provider.provider_id()],
                |row| row.get(0),
            )
            .optional()?;

        match existing {
            Some(fingerprint) if fingerprint != provider.provider_fingerprint() => {
                Err(RegistryError::ProviderIdentityChanged {
                    provider_id: provider.provider_id().to_string(),
                    expected: fingerprint,
                    actual: provider.provider_fingerprint().to_string(),
                })
            }
            Some(_) => Ok(()),
            None => {
                self.connection.execute(
                    "
                    INSERT INTO mcp_providers (
                        provider_id, provider_fingerprint, transport_kind, endpoint,
                        registered_at_unix_ms
                    ) VALUES (?1, ?2, ?3, ?4, ?5)
                    ",
                    params![
                        provider.provider_id(),
                        provider.provider_fingerprint(),
                        provider.transport_kind(),
                        provider.endpoint(),
                        now_unix_ms
                    ],
                )?;
                Ok(())
            }
        }
    }

    pub fn reconcile(
        &mut self,
        provider: &ProviderIdentity,
        snapshot: &DiscoverySnapshot,
        ledger: &mut AuditLedger,
        now_unix_ms: i64,
    ) -> Result<DiscoveryReport, RegistryError> {
        self.ensure_provider(provider)?;
        if snapshot.protocol_revision != MCP_PROTOCOL_REVISION {
            return Err(RegistryError::UnsupportedProtocolRevision(
                snapshot.protocol_revision.clone(),
            ));
        }
        if snapshot.tools.len() > MAX_DISCOVERED_TOOLS {
            return Err(RegistryError::TooManyTools(snapshot.tools.len()));
        }

        let mut normalized = snapshot.tools.clone();
        normalized.sort_by(|left, right| left.name.cmp(&right.name));

        let mut seen = BTreeSet::new();
        for tool in &normalized {
            if !seen.insert(tool.name.clone()) {
                return Err(RegistryError::DuplicateTool(tool.name.clone()));
            }
            validate_tool_descriptor(tool)?;
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut report = DiscoveryReport::default();

        for tool in &normalized {
            let schema_fingerprint = schema_fingerprint(tool)?;
            let descriptor_fingerprint = descriptor_fingerprint(tool)?;
            let identity_fingerprint = tool_identity_fingerprint(
                provider.provider_fingerprint(),
                &tool.name,
                &schema_fingerprint,
            );
            let descriptor_json = serde_json::to_string(tool)?;

            let previous = transaction
                .query_row(
                    "
                    SELECT provider_id, tool_name, state,
                           trusted_schema_fingerprint, trusted_descriptor_fingerprint,
                           trusted_identity_fingerprint, observed_schema_fingerprint,
                           observed_descriptor_fingerprint, observed_identity_fingerprint,
                           trusted_descriptor_json, observed_descriptor_json,
                           first_seen_unix_ms, last_seen_unix_ms
                    FROM mcp_tools
                    WHERE provider_id = ?1 AND tool_name = ?2
                    ",
                    params![provider.provider_id(), tool.name],
                    tool_from_row,
                )
                .optional()?;

            match previous {
                None => {
                    transaction.execute(
                        "
                        INSERT INTO mcp_tools (
                            provider_id, tool_name, state,
                            trusted_schema_fingerprint, trusted_descriptor_fingerprint,
                            trusted_identity_fingerprint, observed_schema_fingerprint,
                            observed_descriptor_fingerprint, observed_identity_fingerprint,
                            trusted_descriptor_json, observed_descriptor_json,
                            first_seen_unix_ms, last_seen_unix_ms
                        ) VALUES (
                            ?1, ?2, 'ACTIVE',
                            ?3, ?4, ?5, ?3, ?4, ?5, ?6, ?6, ?7, ?7
                        )
                        ",
                        params![
                            provider.provider_id(),
                            tool.name,
                            schema_fingerprint,
                            descriptor_fingerprint,
                            identity_fingerprint,
                            descriptor_json,
                            now_unix_ms
                        ],
                    )?;
                    report.added += 1;
                }
                Some(previous)
                    if previous.trusted_schema_fingerprint == schema_fingerprint
                        && previous.trusted_descriptor_fingerprint == descriptor_fingerprint
                        && previous.trusted_identity_fingerprint == identity_fingerprint =>
                {
                    transaction.execute(
                        "
                        UPDATE mcp_tools
                        SET state = 'ACTIVE',
                            observed_schema_fingerprint = ?3,
                            observed_descriptor_fingerprint = ?4,
                            observed_identity_fingerprint = ?5,
                            observed_descriptor_json = ?6,
                            last_seen_unix_ms = ?7
                        WHERE provider_id = ?1 AND tool_name = ?2
                        ",
                        params![
                            provider.provider_id(),
                            tool.name,
                            schema_fingerprint,
                            descriptor_fingerprint,
                            identity_fingerprint,
                            descriptor_json,
                            now_unix_ms
                        ],
                    )?;
                    report.unchanged += 1;
                }
                Some(previous) => {
                    let newly_observed = previous.observed_schema_fingerprint != schema_fingerprint
                        || previous.observed_descriptor_fingerprint != descriptor_fingerprint
                        || previous.observed_identity_fingerprint != identity_fingerprint
                        || previous.state != ToolState::Changed;

                    if newly_observed {
                        ledger.append(tool_change_event(
                            provider,
                            tool,
                            now_unix_ms,
                            "DRIFT_DETECTED",
                            json!({
                                "trusted_schema_fingerprint": previous.trusted_schema_fingerprint,
                                "observed_schema_fingerprint": schema_fingerprint,
                                "trusted_descriptor_fingerprint": previous.trusted_descriptor_fingerprint,
                                "observed_descriptor_fingerprint": descriptor_fingerprint,
                                "trusted_identity_fingerprint": previous.trusted_identity_fingerprint,
                                "observed_identity_fingerprint": identity_fingerprint,
                            }),
                        ))?;
                    }

                    transaction.execute(
                        "
                        UPDATE mcp_tools
                        SET state = 'CHANGED',
                            observed_schema_fingerprint = ?3,
                            observed_descriptor_fingerprint = ?4,
                            observed_identity_fingerprint = ?5,
                            observed_descriptor_json = ?6,
                            last_seen_unix_ms = ?7
                        WHERE provider_id = ?1 AND tool_name = ?2
                        ",
                        params![
                            provider.provider_id(),
                            tool.name,
                            schema_fingerprint,
                            descriptor_fingerprint,
                            identity_fingerprint,
                            descriptor_json,
                            now_unix_ms
                        ],
                    )?;
                    report.changed += 1;
                }
            }
        }

        let mut statement = transaction.prepare(
            "
            SELECT provider_id, tool_name, state,
                   trusted_schema_fingerprint, trusted_descriptor_fingerprint,
                   trusted_identity_fingerprint, observed_schema_fingerprint,
                   observed_descriptor_fingerprint, observed_identity_fingerprint,
                   trusted_descriptor_json, observed_descriptor_json,
                   first_seen_unix_ms, last_seen_unix_ms
            FROM mcp_tools
            WHERE provider_id = ?1
            ",
        )?;
        let existing = statement
            .query_map([provider.provider_id()], tool_from_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);

        for tool in existing {
            if seen.contains(&tool.tool_name) {
                continue;
            }

            if tool.state != ToolState::Missing {
                ledger.append(tool_change_event(
                    provider,
                    &tool.trusted_descriptor,
                    now_unix_ms,
                    "TOOL_MISSING",
                    json!({
                        "trusted_schema_fingerprint": tool.trusted_schema_fingerprint,
                        "trusted_identity_fingerprint": tool.trusted_identity_fingerprint,
                    }),
                ))?;
            }

            transaction.execute(
                "
                UPDATE mcp_tools
                SET state = 'MISSING', last_seen_unix_ms = ?3
                WHERE provider_id = ?1 AND tool_name = ?2
                ",
                params![provider.provider_id(), tool.tool_name, now_unix_ms],
            )?;
            report.missing += 1;
        }

        transaction.commit()?;
        Ok(report)
    }

    pub fn active_tool(
        &self,
        provider: &ProviderIdentity,
        tool_name: &str,
    ) -> Result<ToolRecord, RegistryError> {
        self.ensure_provider(provider)?;
        let tool = self
            .connection
            .query_row(
                "
                SELECT provider_id, tool_name, state,
                       trusted_schema_fingerprint, trusted_descriptor_fingerprint,
                       trusted_identity_fingerprint, observed_schema_fingerprint,
                       observed_descriptor_fingerprint, observed_identity_fingerprint,
                       trusted_descriptor_json, observed_descriptor_json,
                       first_seen_unix_ms, last_seen_unix_ms
                FROM mcp_tools
                WHERE provider_id = ?1 AND tool_name = ?2
                ",
                params![provider.provider_id(), tool_name],
                tool_from_row,
            )
            .optional()?
            .ok_or_else(|| RegistryError::UnknownTool(tool_name.to_string()))?;

        match tool.state {
            ToolState::Active => Ok(tool),
            ToolState::Changed => Err(RegistryError::ToolChanged(tool_name.to_string())),
            ToolState::Missing => Err(RegistryError::ToolMissing(tool_name.to_string())),
        }
    }

    pub fn accept_observed_change(
        &mut self,
        provider: &ProviderIdentity,
        tool_name: &str,
        expected_observed_identity: &str,
        resolver_principal: &str,
        ledger: &mut AuditLedger,
        now_unix_ms: i64,
    ) -> Result<ToolRecord, RegistryError> {
        self.ensure_provider(provider)?;
        if resolver_principal.trim().is_empty() {
            return Err(RegistryError::InvalidResolver);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tool = transaction
            .query_row(
                "
                SELECT provider_id, tool_name, state,
                       trusted_schema_fingerprint, trusted_descriptor_fingerprint,
                       trusted_identity_fingerprint, observed_schema_fingerprint,
                       observed_descriptor_fingerprint, observed_identity_fingerprint,
                       trusted_descriptor_json, observed_descriptor_json,
                       first_seen_unix_ms, last_seen_unix_ms
                FROM mcp_tools
                WHERE provider_id = ?1 AND tool_name = ?2
                ",
                params![provider.provider_id(), tool_name],
                tool_from_row,
            )
            .optional()?
            .ok_or_else(|| RegistryError::UnknownTool(tool_name.to_string()))?;

        if tool.state != ToolState::Changed {
            return Err(RegistryError::ToolNotChanged(tool_name.to_string()));
        }
        if tool.observed_identity_fingerprint != expected_observed_identity {
            return Err(RegistryError::ObservedIdentityMismatch {
                expected: expected_observed_identity.to_string(),
                actual: tool.observed_identity_fingerprint,
            });
        }

        ledger.append(tool_change_event(
            provider,
            &tool.observed_descriptor,
            now_unix_ms,
            "DRIFT_ACCEPTED",
            json!({
                "resolver_principal": resolver_principal,
                "previous_identity_fingerprint": tool.trusted_identity_fingerprint,
                "accepted_identity_fingerprint": tool.observed_identity_fingerprint,
            }),
        ))?;

        transaction.execute(
            "
            UPDATE mcp_tools
            SET state = 'ACTIVE',
                trusted_schema_fingerprint = observed_schema_fingerprint,
                trusted_descriptor_fingerprint = observed_descriptor_fingerprint,
                trusted_identity_fingerprint = observed_identity_fingerprint,
                trusted_descriptor_json = observed_descriptor_json
            WHERE provider_id = ?1 AND tool_name = ?2
            ",
            params![provider.provider_id(), tool_name],
        )?;
        transaction.commit()?;

        self.active_tool(provider, tool_name)
    }

    fn ensure_provider(&self, provider: &ProviderIdentity) -> Result<(), RegistryError> {
        let fingerprint: Option<String> = self
            .connection
            .query_row(
                "SELECT provider_fingerprint FROM mcp_providers WHERE provider_id = ?1",
                [provider.provider_id()],
                |row| row.get(0),
            )
            .optional()?;

        match fingerprint {
            Some(expected) if expected == provider.provider_fingerprint() => Ok(()),
            Some(expected) => Err(RegistryError::ProviderIdentityChanged {
                provider_id: provider.provider_id().to_string(),
                expected,
                actual: provider.provider_fingerprint().to_string(),
            }),
            None => Err(RegistryError::UnknownProvider(
                provider.provider_id().to_string(),
            )),
        }
    }
}

fn tool_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ToolRecord> {
    let state: String = row.get(2)?;
    let trusted_json: String = row.get(9)?;
    let observed_json: String = row.get(10)?;
    let trusted_descriptor = serde_json::from_str(&trusted_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            trusted_json.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    let observed_descriptor = serde_json::from_str(&observed_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            observed_json.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;

    Ok(ToolRecord {
        provider_id: row.get(0)?,
        tool_name: row.get(1)?,
        state: ToolState::from_str(&state).ok_or_else(|| {
            rusqlite::Error::InvalidColumnType(2, "state".into(), rusqlite::types::Type::Text)
        })?,
        trusted_schema_fingerprint: row.get(3)?,
        trusted_descriptor_fingerprint: row.get(4)?,
        trusted_identity_fingerprint: row.get(5)?,
        observed_schema_fingerprint: row.get(6)?,
        observed_descriptor_fingerprint: row.get(7)?,
        observed_identity_fingerprint: row.get(8)?,
        trusted_descriptor,
        observed_descriptor,
        first_seen_unix_ms: row.get(11)?,
        last_seen_unix_ms: row.get(12)?,
    })
}

fn tool_change_event(
    provider: &ProviderIdentity,
    tool: &ToolDescriptor,
    timestamp_unix_ms: i64,
    action: &str,
    metadata: serde_json::Value,
) -> AuditEntryInput {
    AuditEntryInput {
        timestamp_unix_ms,
        event_type: AuditEventType::ToolChanged,
        session_id: None,
        request_id: None,
        operation: Some("mcp.tool.registry".into()),
        resource_kind: Some("mcp-tool".into()),
        resource_value: Some(format!("{}/{}", provider.provider_id(), tool.name)),
        decision: None,
        policy_rule: None,
        reason: Some(action.to_string()),
        credential_ref: None,
        metadata: json!({
            "provider_id": provider.provider_id(),
            "provider_fingerprint": provider.provider_fingerprint(),
            "tool_name": tool.name,
            "action": action,
            "change": metadata,
        }),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("tool registry database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("tool registry audit error: {0}")]
    Audit(#[from] AuditError),
    #[error("tool schema error: {0}")]
    Schema(#[from] SchemaError),
    #[error("tool descriptor serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("unknown MCP provider: {0}")]
    UnknownProvider(String),
    #[error("provider identity changed for {provider_id}: expected {expected}, got {actual}")]
    ProviderIdentityChanged {
        provider_id: String,
        expected: String,
        actual: String,
    },
    #[error("unsupported MCP protocol revision: {0}")]
    UnsupportedProtocolRevision(String),
    #[error("MCP server advertised too many tools: {0}")]
    TooManyTools(usize),
    #[error("MCP discovery returned duplicate tool name: {0}")]
    DuplicateTool(String),
    #[error("unknown MCP tool: {0}")]
    UnknownTool(String),
    #[error("MCP tool schema or descriptor changed: {0}")]
    ToolChanged(String),
    #[error("MCP tool disappeared from discovery: {0}")]
    ToolMissing(String),
    #[error("MCP tool is not awaiting change acceptance: {0}")]
    ToolNotChanged(String),
    #[error("observed tool identity mismatch: expected {expected}, got {actual}")]
    ObservedIdentityMismatch { expected: String, actual: String },
    #[error("resolver principal cannot be empty")]
    InvalidResolver,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProviderIdentity;
    use serde_json::json;

    fn provider(id: &str, binding: &str) -> ProviderIdentity {
        ProviderIdentity::new(id, "test", "in-memory", &json!({"binding": binding}))
            .expect("provider")
    }

    fn tool(name: &str, path_type: &str) -> ToolDescriptor {
        ToolDescriptor {
            name: name.into(),
            title: None,
            description: Some("Read a file".into()),
            input_schema: json!({
                "type":"object",
                "properties":{"path":{"type":path_type}},
                "required":["path"],
                "additionalProperties":false
            }),
            output_schema: None,
            annotations: None,
        }
    }

    fn snapshot(tool: ToolDescriptor) -> DiscoverySnapshot {
        DiscoverySnapshot {
            protocol_revision: MCP_PROTOCOL_REVISION.into(),
            reported_server: Some(crate::ReportedServerInfo {
                name: "untrusted-name".into(),
                version: "1.0".into(),
            }),
            tools: vec![tool],
        }
    }

    #[test]
    fn same_tool_name_on_different_provider_has_different_identity(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let first = provider("trusted-files", "one");
        let second = provider("malicious-files", "two");
        let descriptor = tool("read_file", "string");
        let schema = schema_fingerprint(&descriptor)?;

        assert_ne!(
            tool_identity_fingerprint(first.provider_fingerprint(), "read_file", &schema),
            tool_identity_fingerprint(second.provider_fingerprint(), "read_file", &schema)
        );
        Ok(())
    }

    #[test]
    fn schema_drift_blocks_tool_until_explicitly_accepted(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let provider = provider("trusted-files", "one");
        let mut registry = ToolRegistry::in_memory()?;
        let mut ledger = AuditLedger::in_memory()?;
        registry.register_provider(&provider, 1_000)?;

        registry.reconcile(
            &provider,
            &snapshot(tool("read_file", "string")),
            &mut ledger,
            1_100,
        )?;
        assert_eq!(
            registry.active_tool(&provider, "read_file")?.state,
            ToolState::Active
        );

        let report = registry.reconcile(
            &provider,
            &snapshot(tool("read_file", "integer")),
            &mut ledger,
            1_200,
        )?;
        assert_eq!(report.changed, 1);
        assert!(matches!(
            registry.active_tool(&provider, "read_file"),
            Err(RegistryError::ToolChanged(_))
        ));

        let changed = registry.connection.query_row(
            "
                SELECT provider_id, tool_name, state,
                       trusted_schema_fingerprint, trusted_descriptor_fingerprint,
                       trusted_identity_fingerprint, observed_schema_fingerprint,
                       observed_descriptor_fingerprint, observed_identity_fingerprint,
                       trusted_descriptor_json, observed_descriptor_json,
                       first_seen_unix_ms, last_seen_unix_ms
                FROM mcp_tools
                WHERE provider_id = ?1 AND tool_name = 'read_file'
                ",
            [provider.provider_id()],
            tool_from_row,
        )?;

        registry.accept_observed_change(
            &provider,
            "read_file",
            &changed.observed_identity_fingerprint,
            "local-user",
            &mut ledger,
            1_300,
        )?;

        assert!(registry.active_tool(&provider, "read_file").is_ok());
        assert_eq!(
            ledger
                .entries()?
                .iter()
                .filter(|entry| entry.event_type == "TOOL_CHANGED")
                .count(),
            2
        );
        Ok(())
    }

    #[test]
    fn provider_binding_change_is_rejected() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let original = provider("trusted-files", "one");
        let changed = provider("trusted-files", "different");
        let mut registry = ToolRegistry::in_memory()?;
        registry.register_provider(&original, 1_000)?;

        assert!(matches!(
            registry.register_provider(&changed, 1_100),
            Err(RegistryError::ProviderIdentityChanged { .. })
        ));
        Ok(())
    }
}

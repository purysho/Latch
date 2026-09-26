use crate::model::{McpUpstream, ProviderIdentity};
use crate::registry::{DiscoveryReport, RegistryError, ToolRegistry};
use crate::schema::{validate_arguments, validate_output, SchemaError};
use latch_approvals::{ExecutionPermit, PermitSource};
use latch_audit::{AuditEntryInput, AuditError, AuditEventType, AuditLedger};
use latch_core::{ActionRequest, Effect, Resource};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const MCP_OPERATION: &str = "mcp.tool.call";
pub const MCP_RESOURCE_KIND: &str = "mcp-tool";
pub const MAX_RESULT_BYTES: usize = 4 * 1024 * 1024;

pub struct McpProxy<U: McpUpstream> {
    provider: ProviderIdentity,
    registry: ToolRegistry,
    upstream: U,
}

impl<U: McpUpstream> McpProxy<U> {
    pub fn new(
        provider: ProviderIdentity,
        mut registry: ToolRegistry,
        upstream: U,
        now_unix_ms: i64,
    ) -> Result<Self, ProxyError> {
        registry.register_provider(&provider, now_unix_ms)?;
        Ok(Self {
            provider,
            registry,
            upstream,
        })
    }

    pub fn provider(&self) -> &ProviderIdentity {
        &self.provider
    }

    pub fn registry(&self) -> &ToolRegistry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut ToolRegistry {
        &mut self.registry
    }

    pub fn upstream(&self) -> &U {
        &self.upstream
    }

    pub fn discover(
        &mut self,
        ledger: &mut AuditLedger,
        now_unix_ms: i64,
    ) -> Result<DiscoveryReport, ProxyError> {
        let snapshot = self.upstream.discover()?;
        Ok(self
            .registry
            .reconcile(&self.provider, &snapshot, ledger, now_unix_ms)?)
    }

    pub fn prepare_call(
        &self,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        tool_name: &str,
        arguments: Value,
    ) -> Result<ActionRequest, ProxyError> {
        let tool = self.registry.active_tool(&self.provider, tool_name)?;
        validate_arguments(&tool.trusted_descriptor.input_schema, &arguments)?;

        let resource_value = resource_value(
            self.provider.provider_id(),
            tool_name,
            &tool.trusted_identity_fingerprint,
        );

        Ok(ActionRequest {
            request_id: request_id.into(),
            session_id: session_id.into(),
            operation: MCP_OPERATION.into(),
            resource: Resource {
                kind: MCP_RESOURCE_KIND.into(),
                value: resource_value,
            },
            arguments: json!({
                "provider_id": self.provider.provider_id(),
                "provider_fingerprint": self.provider.provider_fingerprint(),
                "tool_name": tool_name,
                "schema_fingerprint": tool.trusted_schema_fingerprint,
                "descriptor_fingerprint": tool.trusted_descriptor_fingerprint,
                "tool_identity_fingerprint": tool.trusted_identity_fingerprint,
                "tool_arguments": arguments,
            }),
        })
    }

    pub fn execute(
        &mut self,
        permit: ExecutionPermit,
        ledger: &mut AuditLedger,
        now_unix_ms: i64,
    ) -> Result<Value, ProxyError> {
        permit
            .validate_at(now_unix_ms)
            .map_err(|error| ProxyError::InvalidPermit(error.to_string()))?;

        let request = permit.request();
        if request.operation != MCP_OPERATION || request.resource.kind != MCP_RESOURCE_KIND {
            return Err(ProxyError::InvalidPermit(
                "permit is not for an MCP tool call".into(),
            ));
        }

        let provider_id = argument_text(&request.arguments, "provider_id")?;
        let provider_fingerprint = argument_text(&request.arguments, "provider_fingerprint")?;
        let tool_name = argument_text(&request.arguments, "tool_name")?;
        let expected_schema = argument_text(&request.arguments, "schema_fingerprint")?;
        let expected_descriptor = argument_text(&request.arguments, "descriptor_fingerprint")?;
        let expected_identity = argument_text(&request.arguments, "tool_identity_fingerprint")?;
        let tool_arguments = request
            .arguments
            .get("tool_arguments")
            .cloned()
            .ok_or_else(|| ProxyError::InvalidPermit("missing tool_arguments".into()))?;

        if provider_id != self.provider.provider_id()
            || provider_fingerprint != self.provider.provider_fingerprint()
        {
            return Err(ProxyError::ProviderMismatch);
        }

        let expected_resource = resource_value(provider_id, tool_name, expected_identity);
        if request.resource.value != expected_resource {
            return Err(ProxyError::InvalidPermit(
                "MCP resource does not match provider/tool identity".into(),
            ));
        }

        // Refresh immediately before forwarding. A schema or descriptor change between
        // authorization and execution blocks the call rather than inheriting stale trust.
        let snapshot = self.upstream.discover()?;
        self.registry
            .reconcile(&self.provider, &snapshot, ledger, now_unix_ms)?;

        let tool = self.registry.active_tool(&self.provider, tool_name)?;
        if tool.trusted_schema_fingerprint != expected_schema
            || tool.trusted_descriptor_fingerprint != expected_descriptor
            || tool.trusted_identity_fingerprint != expected_identity
        {
            return Err(ProxyError::ToolIdentityMismatch);
        }

        validate_arguments(&tool.trusted_descriptor.input_schema, &tool_arguments)?;

        ledger.append(forwarded_event(
            &permit,
            &self.provider,
            tool_name,
            expected_schema,
            expected_identity,
            &tool_arguments,
            now_unix_ms,
        ))?;

        let result = self.upstream.call_tool(tool_name, &tool_arguments)?;
        let result_bytes = serde_json::to_vec(&result)
            .map_err(|error| ProxyError::ResultSerialization(error.to_string()))?;
        if result_bytes.len() > MAX_RESULT_BYTES {
            ledger.append(result_event(
                &permit,
                &self.provider,
                tool_name,
                expected_identity,
                now_unix_ms,
                ResultAudit {
                    outcome: "RESULT_TOO_LARGE",
                    bytes: result_bytes.len(),
                    sha256: &sha256_bytes(&result_bytes),
                },
            ))?;
            return Err(ProxyError::ResultTooLarge(result_bytes.len()));
        }

        if let Some(output_schema) = &tool.trusted_descriptor.output_schema {
            let structured = result
                .get("structuredContent")
                .ok_or(ProxyError::MissingStructuredContent)?;
            if let Err(error) = validate_output(output_schema, structured) {
                ledger.append(result_event(
                    &permit,
                    &self.provider,
                    tool_name,
                    expected_identity,
                    now_unix_ms,
                    ResultAudit {
                        outcome: "INVALID_OUTPUT_SCHEMA",
                        bytes: result_bytes.len(),
                        sha256: &sha256_bytes(&result_bytes),
                    },
                ))?;
                return Err(ProxyError::Schema(error));
            }
        }

        ledger.append(result_event(
            &permit,
            &self.provider,
            tool_name,
            expected_identity,
            now_unix_ms,
            ResultAudit {
                outcome: "COMPLETED",
                bytes: result_bytes.len(),
                sha256: &sha256_bytes(&result_bytes),
            },
        ))?;

        Ok(result)
    }
}

fn resource_value(provider_id: &str, tool_name: &str, identity_fingerprint: &str) -> String {
    format!("{provider_id}/{tool_name}@{identity_fingerprint}")
}

fn argument_text<'a>(arguments: &'a Value, key: &str) -> Result<&'a str, ProxyError> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ProxyError::InvalidPermit(format!("missing or invalid {key}")))
}

fn permit_source(source: &PermitSource) -> (&'static str, Option<&str>) {
    match source {
        PermitSource::Policy => ("POLICY", None),
        PermitSource::ApprovalOnce { grant_id } => ("APPROVAL_ONCE", Some(grant_id)),
        PermitSource::ApprovalSession { grant_id } => ("APPROVAL_SESSION", Some(grant_id)),
    }
}

fn forwarded_event(
    permit: &ExecutionPermit,
    provider: &ProviderIdentity,
    tool_name: &str,
    schema_fingerprint: &str,
    identity_fingerprint: &str,
    tool_arguments: &Value,
    timestamp_unix_ms: i64,
) -> AuditEntryInput {
    let request = permit.request();
    let (authority, grant_id) = permit_source(permit.source());
    AuditEntryInput {
        timestamp_unix_ms,
        event_type: AuditEventType::ToolForwarded,
        session_id: Some(request.session_id.clone()),
        request_id: Some(request.request_id.clone()),
        operation: Some(request.operation.clone()),
        resource_kind: Some(request.resource.kind.clone()),
        resource_value: Some(request.resource.value.clone()),
        decision: Some(Effect::Allow),
        policy_rule: permit.rule_id().map(str::to_string),
        reason: Some("MCP tool call forwarded".into()),
        credential_ref: None,
        metadata: json!({
            "adapter": "mcp",
            "provider_id": provider.provider_id(),
            "provider_fingerprint": provider.provider_fingerprint(),
            "tool_name": tool_name,
            "schema_fingerprint": schema_fingerprint,
            "tool_identity_fingerprint": identity_fingerprint,
            "authority": authority,
            "grant_id": grant_id,
            "arguments_sha256": value_sha256(tool_arguments),
        }),
    }
}

struct ResultAudit<'a> {
    outcome: &'a str,
    bytes: usize,
    sha256: &'a str,
}

fn result_event(
    permit: &ExecutionPermit,
    provider: &ProviderIdentity,
    tool_name: &str,
    identity_fingerprint: &str,
    timestamp_unix_ms: i64,
    result: ResultAudit<'_>,
) -> AuditEntryInput {
    let request = permit.request();
    AuditEntryInput {
        timestamp_unix_ms,
        event_type: AuditEventType::ToolResult,
        session_id: Some(request.session_id.clone()),
        request_id: Some(request.request_id.clone()),
        operation: Some(request.operation.clone()),
        resource_kind: Some(request.resource.kind.clone()),
        resource_value: Some(request.resource.value.clone()),
        decision: Some(Effect::Allow),
        policy_rule: permit.rule_id().map(str::to_string),
        reason: Some(result.outcome.to_string()),
        credential_ref: None,
        metadata: json!({
            "adapter": "mcp",
            "provider_id": provider.provider_id(),
            "provider_fingerprint": provider.provider_fingerprint(),
            "tool_name": tool_name,
            "tool_identity_fingerprint": identity_fingerprint,
            "outcome": result.outcome,
            "result_bytes": result.bytes,
            "result_sha256": result.sha256,
        }),
    }
}

fn value_sha256(value: &Value) -> String {
    match serde_json::to_vec(value) {
        Ok(bytes) => sha256_bytes(&bytes),
        Err(_) => "SERIALIZATION_FAILED".into(),
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("MCP registry error: {0}")]
    Registry(#[from] RegistryError),
    #[error("MCP schema error: {0}")]
    Schema(#[from] SchemaError),
    #[error("MCP upstream error: {0}")]
    Upstream(#[from] crate::UpstreamError),
    #[error("MCP audit error: {0}")]
    Audit(#[from] AuditError),
    #[error("invalid MCP execution permit: {0}")]
    InvalidPermit(String),
    #[error("MCP provider binding does not match permit")]
    ProviderMismatch,
    #[error("MCP tool identity changed after authorization")]
    ToolIdentityMismatch,
    #[error("MCP tool declared outputSchema but returned no structuredContent")]
    MissingStructuredContent,
    #[error("MCP result exceeds size limit: {0} bytes")]
    ResultTooLarge(usize),
    #[error("failed to serialize MCP tool result: {0}")]
    ResultSerialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DiscoverySnapshot, ReportedServerInfo, ToolDescriptor, UpstreamError};
    use latch_approvals::ApprovalStore;
    use latch_core::{evaluate, Policy, Rule, Session};
    use serde_json::json;
    use std::collections::VecDeque;

    struct MockUpstream {
        discoveries: VecDeque<DiscoverySnapshot>,
        last_discovery: Option<DiscoverySnapshot>,
        result: Value,
        calls: usize,
    }

    impl MockUpstream {
        fn new(discoveries: Vec<DiscoverySnapshot>, result: Value) -> Self {
            Self {
                discoveries: discoveries.into(),
                last_discovery: None,
                result,
                calls: 0,
            }
        }
    }

    impl McpUpstream for MockUpstream {
        fn discover(&mut self) -> Result<DiscoverySnapshot, UpstreamError> {
            let snapshot = self
                .discoveries
                .pop_front()
                .or_else(|| self.last_discovery.clone())
                .ok_or_else(|| UpstreamError::new("no discovery snapshot"))?;
            self.last_discovery = Some(snapshot.clone());
            Ok(snapshot)
        }

        fn call_tool(
            &mut self,
            _tool_name: &str,
            _arguments: &Value,
        ) -> Result<Value, UpstreamError> {
            self.calls += 1;
            Ok(self.result.clone())
        }
    }

    fn provider(id: &str, binding: &str) -> ProviderIdentity {
        ProviderIdentity::new(id, "test", "in-memory", &json!({"binding":binding}))
            .expect("provider")
    }

    fn descriptor(path_type: &str) -> ToolDescriptor {
        ToolDescriptor {
            name: "read_file".into(),
            title: Some("Read file".into()),
            description: Some("Read a file".into()),
            input_schema: json!({
                "type":"object",
                "properties":{"path":{"type":path_type}},
                "required":["path"],
                "additionalProperties":false
            }),
            output_schema: Some(json!({
                "type":"object",
                "properties":{"text":{"type":"string"}},
                "required":["text"],
                "additionalProperties":false
            })),
            annotations: None,
        }
    }

    fn snapshot(tool: ToolDescriptor) -> DiscoverySnapshot {
        DiscoverySnapshot {
            protocol_revision: crate::MCP_PROTOCOL_REVISION.into(),
            reported_server: Some(ReportedServerInfo {
                name: "self-reported".into(),
                version: "1.0".into(),
            }),
            tools: vec![tool],
        }
    }

    fn session(id: &str) -> Session {
        Session {
            id: id.into(),
            principal: "local-user".into(),
            purpose: "mcp-test".into(),
            expires_at_unix: 10_000,
            revoked: false,
        }
    }

    fn allow_policy(resource: &str) -> Policy {
        Policy {
            version: 1,
            rules: vec![Rule {
                id: "allow-mcp-tool".into(),
                effect: Effect::Allow,
                operation: MCP_OPERATION.into(),
                resource_kind: MCP_RESOURCE_KIND.into(),
                resource_prefix: resource.into(),
            }],
        }
    }

    fn permit_for(
        proxy: &McpProxy<MockUpstream>,
        session: &Session,
        request: &ActionRequest,
        now_unix_ms: i64,
    ) -> ExecutionPermit {
        let policy = allow_policy(&request.resource.value);
        let now_unix = u64::try_from(now_unix_ms / 1_000).expect("non-negative test time");
        let decision = evaluate(session, &policy, request, now_unix);
        let mut approvals = ApprovalStore::in_memory().expect("approval store");
        approvals
            .authorize(session, request, &decision, now_unix_ms)
            .expect("permit")
    }

    #[test]
    fn authorized_tool_call_is_validated_and_forwarded(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let provider = provider("trusted-files", "one");
        let upstream = MockUpstream::new(
            vec![
                snapshot(descriptor("string")),
                snapshot(descriptor("string")),
            ],
            json!({
                "content":[{"type":"text","text":"hello"}],
                "structuredContent":{"text":"hello"}
            }),
        );
        let registry = ToolRegistry::in_memory()?;
        let mut proxy = McpProxy::new(provider, registry, upstream, 1_000)?;
        let mut ledger = AuditLedger::in_memory()?;
        proxy.discover(&mut ledger, 1_100)?;

        let session = session("lat_mcp");
        let request = proxy.prepare_call(
            "req_mcp",
            &session.id,
            "read_file",
            json!({"path":"README.md"}),
        )?;
        let policy = allow_policy(&request.resource.value);
        let decision = evaluate(&session, &policy, &request, 1);
        ledger.record_authorization(1_150, &session, &request, &decision)?;
        let permit = {
            let mut approvals = ApprovalStore::in_memory()?;
            approvals.authorize(&session, &request, &decision, 1_200)?
        };

        let result = proxy.execute(permit, &mut ledger, 1_300)?;

        assert_eq!(result["structuredContent"]["text"], "hello");
        assert_eq!(proxy.upstream().calls, 1);
        let events = ledger.entries()?;
        assert!(events
            .iter()
            .any(|entry| entry.event_type == "TOOL_FORWARDED"));
        assert!(events.iter().any(|entry| entry.event_type == "TOOL_RESULT"));
        Ok(())
    }

    #[test]
    fn spoofed_provider_with_same_tool_name_does_not_inherit_trust(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let trusted_provider = provider("trusted-files", "trusted-binding");
        let malicious_provider = provider("malicious-files", "malicious-binding");

        let trusted_upstream = MockUpstream::new(vec![snapshot(descriptor("string"))], json!({}));
        let malicious_upstream = MockUpstream::new(vec![snapshot(descriptor("string"))], json!({}));

        let mut trusted = McpProxy::new(
            trusted_provider,
            ToolRegistry::in_memory()?,
            trusted_upstream,
            1_000,
        )?;
        let mut malicious = McpProxy::new(
            malicious_provider,
            ToolRegistry::in_memory()?,
            malicious_upstream,
            1_000,
        )?;
        let mut trusted_ledger = AuditLedger::in_memory()?;
        let mut malicious_ledger = AuditLedger::in_memory()?;
        trusted.discover(&mut trusted_ledger, 1_100)?;
        malicious.discover(&mut malicious_ledger, 1_100)?;

        let session = session("lat_spoof");
        let trusted_request = trusted.prepare_call(
            "req_trusted",
            &session.id,
            "read_file",
            json!({"path":"README.md"}),
        )?;
        let malicious_request = malicious.prepare_call(
            "req_malicious",
            &session.id,
            "read_file",
            json!({"path":"README.md"}),
        )?;

        let policy = allow_policy(&trusted_request.resource.value);
        assert_eq!(
            evaluate(&session, &policy, &trusted_request, 1).effect(),
            Effect::Allow
        );
        assert_eq!(
            evaluate(&session, &policy, &malicious_request, 1).effect(),
            Effect::Deny
        );
        assert_ne!(
            trusted_request.resource.value,
            malicious_request.resource.value
        );
        Ok(())
    }

    #[test]
    fn schema_drift_between_authorization_and_forwarding_blocks_call(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let provider = provider("trusted-files", "one");
        let upstream = MockUpstream::new(
            vec![
                snapshot(descriptor("string")),
                snapshot(descriptor("integer")),
            ],
            json!({
                "structuredContent":{"text":"should not run"}
            }),
        );
        let registry = ToolRegistry::in_memory()?;
        let mut proxy = McpProxy::new(provider, registry, upstream, 1_000)?;
        let mut ledger = AuditLedger::in_memory()?;
        proxy.discover(&mut ledger, 1_100)?;

        let session = session("lat_drift");
        let request = proxy.prepare_call(
            "req_drift",
            &session.id,
            "read_file",
            json!({"path":"README.md"}),
        )?;
        let permit = permit_for(&proxy, &session, &request, 1_200);

        assert!(matches!(
            proxy.execute(permit, &mut ledger, 1_300),
            Err(ProxyError::Registry(RegistryError::ToolChanged(_)))
        ));
        assert_eq!(proxy.upstream().calls, 0);
        assert!(ledger
            .entries()?
            .iter()
            .any(|entry| entry.event_type == "TOOL_CHANGED"));
        Ok(())
    }

    #[test]
    fn invalid_arguments_never_reach_upstream(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let provider = provider("trusted-files", "one");
        let upstream = MockUpstream::new(vec![snapshot(descriptor("string"))], json!({}));
        let registry = ToolRegistry::in_memory()?;
        let mut proxy = McpProxy::new(provider, registry, upstream, 1_000)?;
        let mut ledger = AuditLedger::in_memory()?;
        proxy.discover(&mut ledger, 1_100)?;

        assert!(matches!(
            proxy.prepare_call("req_bad", "lat_bad", "read_file", json!({"path":42})),
            Err(ProxyError::Schema(_))
        ));
        assert_eq!(proxy.upstream().calls, 0);
        Ok(())
    }

    #[test]
    fn invalid_structured_output_is_withheld_after_forwarding(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let provider = provider("trusted-files", "one");
        let upstream = MockUpstream::new(
            vec![
                snapshot(descriptor("string")),
                snapshot(descriptor("string")),
            ],
            json!({
                "content":[{"type":"text","text":"bad"}],
                "structuredContent":{"text":42}
            }),
        );
        let registry = ToolRegistry::in_memory()?;
        let mut proxy = McpProxy::new(provider, registry, upstream, 1_000)?;
        let mut ledger = AuditLedger::in_memory()?;
        proxy.discover(&mut ledger, 1_100)?;

        let session = session("lat_output");
        let request = proxy.prepare_call(
            "req_output",
            &session.id,
            "read_file",
            json!({"path":"README.md"}),
        )?;
        let permit = permit_for(&proxy, &session, &request, 1_200);

        assert!(matches!(
            proxy.execute(permit, &mut ledger, 1_300),
            Err(ProxyError::Schema(_))
        ));
        assert_eq!(proxy.upstream().calls, 1);
        assert!(ledger
            .entries()?
            .iter()
            .any(|entry| entry.reason.as_deref() == Some("INVALID_OUTPUT_SCHEMA")));
        Ok(())
    }
}

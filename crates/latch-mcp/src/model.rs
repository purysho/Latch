use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

pub const MCP_PROTOCOL_REVISION: &str = "2026-07-28";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(
        rename = "outputSchema",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoverySnapshot {
    pub protocol_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_server: Option<ReportedServerInfo>,
    pub tools: Vec<ToolDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIdentity {
    provider_id: String,
    transport_kind: String,
    endpoint: String,
    provider_fingerprint: String,
}

impl ProviderIdentity {
    pub fn new(
        provider_id: impl Into<String>,
        transport_kind: impl Into<String>,
        endpoint: impl Into<String>,
        trusted_binding: &Value,
    ) -> Result<Self, ProviderIdentityError> {
        let provider_id = provider_id.into();
        let transport_kind = transport_kind.into();
        let endpoint = endpoint.into();

        validate_component("provider_id", &provider_id)?;
        validate_component("transport_kind", &transport_kind)?;
        validate_component("endpoint", &endpoint)?;

        let binding = serde_json::to_vec(trusted_binding)
            .map_err(|error| ProviderIdentityError::Binding(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"latch-mcp-provider-v1");
        hash_text(&mut hasher, &provider_id);
        hash_text(&mut hasher, &transport_kind);
        hash_text(&mut hasher, &endpoint);
        hasher.update((binding.len() as u64).to_be_bytes());
        hasher.update(binding);

        Ok(Self {
            provider_id,
            transport_kind,
            endpoint,
            provider_fingerprint: hex::encode(hasher.finalize()),
        })
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn transport_kind(&self) -> &str {
        &self.transport_kind
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn provider_fingerprint(&self) -> &str {
        &self.provider_fingerprint
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderIdentityError {
    #[error("{field} cannot be empty or contain control characters")]
    InvalidComponent { field: &'static str },
    #[error("failed to canonicalize trusted provider binding: {0}")]
    Binding(String),
}

fn validate_component(field: &'static str, value: &str) -> Result<(), ProviderIdentityError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ProviderIdentityError::InvalidComponent { field })
    } else {
        Ok(())
    }
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamError {
    message: String,
}

impl UpstreamError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for UpstreamError {}

pub trait McpUpstream {
    fn discover(&mut self) -> Result<DiscoverySnapshot, UpstreamError>;
    fn call_tool(&mut self, tool_name: &str, arguments: &Value) -> Result<Value, UpstreamError>;
}

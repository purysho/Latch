mod model;
mod proxy;
mod registry;
mod schema;

pub use model::{
    DiscoverySnapshot, McpUpstream, ProviderIdentity, ReportedServerInfo, ToolDescriptor,
    UpstreamError, MCP_PROTOCOL_REVISION,
};
pub use proxy::{McpProxy, ProxyError, MCP_OPERATION, MCP_RESOURCE_KIND};
pub use registry::{DiscoveryReport, RegistryError, ToolRecord, ToolRegistry, ToolState};
pub use schema::{
    descriptor_fingerprint, schema_fingerprint, tool_identity_fingerprint, validate_arguments,
    validate_tool_descriptor, SchemaError,
};

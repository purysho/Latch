use crate::model::{ProviderIdentityError, MCP_PROTOCOL_REVISION};
use crate::{DiscoverySnapshot, McpUpstream, ProviderIdentity, ToolDescriptor, UpstreamError};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

pub const DEFAULT_MAX_STDIO_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_STDIO_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DISCOVERY_PAGES: usize = 64;
const MAX_DISCOVERED_TOOLS: usize = 1024;
const MAX_IGNORED_NOTIFICATIONS: usize = 64;
const SERVER_INFO_META_KEY: &str = "io.modelcontextprotocol/serverInfo";
const PROTOCOL_VERSION_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPABILITIES_META_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
const CLIENT_INFO_META_KEY: &str = "io.modelcontextprotocol/clientInfo";

#[derive(Debug, Clone)]
pub struct StdioProviderConfig {
    provider_id: String,
    executable: PathBuf,
    executable_sha256: String,
    args: Vec<String>,
    working_directory: PathBuf,
    identity_files: BTreeMap<PathBuf, String>,
    inherited_environment: BTreeSet<String>,
    request_timeout: Duration,
    max_message_bytes: usize,
}

impl StdioProviderConfig {
    pub fn new(
        provider_id: impl Into<String>,
        executable: impl AsRef<Path>,
        args: Vec<String>,
        working_directory: impl AsRef<Path>,
    ) -> Result<Self, StdioError> {
        let executable = fs::canonicalize(executable.as_ref())
            .map_err(|error| StdioError::Io("canonicalize MCP executable", error))?;
        if !executable.is_file() {
            return Err(StdioError::InvalidConfiguration(format!(
                "MCP executable is not a regular file: {}",
                executable.display()
            )));
        }

        let working_directory = fs::canonicalize(working_directory.as_ref())
            .map_err(|error| StdioError::Io("canonicalize MCP working directory", error))?;
        if !working_directory.is_dir() {
            return Err(StdioError::InvalidConfiguration(format!(
                "MCP working directory is not a directory: {}",
                working_directory.display()
            )));
        }

        let executable_sha256 = sha256_file(&executable)?;

        Ok(Self {
            provider_id: provider_id.into(),
            executable,
            executable_sha256,
            args,
            working_directory,
            identity_files: BTreeMap::new(),
            inherited_environment: BTreeSet::new(),
            request_timeout: DEFAULT_STDIO_REQUEST_TIMEOUT,
            max_message_bytes: DEFAULT_MAX_STDIO_MESSAGE_BYTES,
        })
    }

    pub fn add_identity_file(mut self, path: impl AsRef<Path>) -> Result<Self, StdioError> {
        let path = fs::canonicalize(path.as_ref())
            .map_err(|error| StdioError::Io("canonicalize MCP identity file", error))?;
        if !path.is_file() {
            return Err(StdioError::InvalidConfiguration(format!(
                "MCP identity material is not a regular file: {}",
                path.display()
            )));
        }
        let digest = sha256_file(&path)?;
        self.identity_files.insert(path, digest);
        Ok(self)
    }

    pub fn inherit_environment(
        mut self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.inherited_environment
            .extend(names.into_iter().map(Into::into));
        self
    }

    pub fn request_timeout(mut self, timeout: Duration) -> Result<Self, StdioError> {
        if timeout.is_zero() {
            return Err(StdioError::InvalidConfiguration(
                "MCP request timeout must be greater than zero".into(),
            ));
        }
        self.request_timeout = timeout;
        Ok(self)
    }

    pub fn max_message_bytes(mut self, max_message_bytes: usize) -> Result<Self, StdioError> {
        if max_message_bytes == 0 {
            return Err(StdioError::InvalidConfiguration(
                "MCP max message size must be greater than zero".into(),
            ));
        }
        self.max_message_bytes = max_message_bytes;
        Ok(self)
    }

    pub fn provider_identity(&self) -> Result<ProviderIdentity, StdioError> {
        self.verify_identity_material()?;

        let mut environment = BTreeMap::new();
        for name in &self.inherited_environment {
            let value_hash = std::env::var_os(name)
                .map(|value| sha256_bytes(value.to_string_lossy().as_bytes()));
            environment.insert(name.clone(), value_hash);
        }

        let identity_files = self
            .identity_files
            .iter()
            .map(|(path, digest)| {
                (
                    path.to_string_lossy().to_string(),
                    Value::String(digest.clone()),
                )
            })
            .collect::<Map<String, Value>>();

        let binding = json!({
            "executable": self.executable.to_string_lossy(),
            "executable_sha256": self.executable_sha256,
            "argv": self.args,
            "working_directory": self.working_directory.to_string_lossy(),
            "identity_files": identity_files,
            "environment_hashes": environment,
            "protocol_revision": MCP_PROTOCOL_REVISION,
        });

        ProviderIdentity::new(
            self.provider_id.clone(),
            "stdio",
            self.executable.to_string_lossy().to_string(),
            &binding,
        )
        .map_err(Into::into)
    }

    fn verify_identity_material(&self) -> Result<(), StdioError> {
        if sha256_file(&self.executable)? != self.executable_sha256 {
            return Err(StdioError::IdentityMaterialChanged(self.executable.clone()));
        }

        for (path, expected) in &self.identity_files {
            if sha256_file(path)? != *expected {
                return Err(StdioError::IdentityMaterialChanged(path.clone()));
            }
        }

        Ok(())
    }

    fn spawn(&self) -> Result<StdioProcess, StdioError> {
        self.verify_identity_material()?;

        let mut command = Command::new(&self.executable);
        command
            .args(&self.args)
            .current_dir(&self.working_directory)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        for name in &self.inherited_environment {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }

        let mut child = command
            .spawn()
            .map_err(|error| StdioError::Io("spawn MCP server", error))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| StdioError::Protocol("MCP child stdin was not piped".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| StdioError::Protocol("MCP child stdout was not piped".into()))?;
        let receiver = spawn_reader(stdout, self.max_message_bytes);

        Ok(StdioProcess {
            child,
            stdin,
            receiver,
        })
    }
}

pub struct StdioUpstream {
    config: StdioProviderConfig,
    provider_identity: ProviderIdentity,
    process: Option<StdioProcess>,
    next_id: u64,
}

impl std::fmt::Debug for StdioUpstream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StdioUpstream")
            .field("provider_id", &self.provider_identity.provider_id())
            .field("endpoint", &self.provider_identity.endpoint())
            .field("running", &self.process.is_some())
            .finish()
    }
}

impl StdioUpstream {
    pub fn new(config: StdioProviderConfig) -> Result<Self, StdioError> {
        let provider_identity = config.provider_identity()?;
        Ok(Self {
            config,
            provider_identity,
            process: None,
            next_id: 1,
        })
    }

    pub fn provider_identity(&self) -> &ProviderIdentity {
        &self.provider_identity
    }

    pub fn close(&mut self) {
        self.process.take();
    }

    fn ensure_process(&mut self) -> Result<(), StdioError> {
        let exited = match self.process.as_mut() {
            Some(process) => process
                .child
                .try_wait()
                .map_err(|error| StdioError::Io("check MCP server status", error))?
                .is_some(),
            None => false,
        };

        if exited {
            self.process.take();
        }
        if self.process.is_none() {
            self.process = Some(self.config.spawn()?);
        }
        Ok(())
    }

    fn request(
        &mut self,
        method: &str,
        mut params: Map<String, Value>,
    ) -> Result<Value, StdioError> {
        self.ensure_process()?;
        let request_id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| StdioError::Protocol("JSON-RPC request id overflow".into()))?;

        params.insert("_meta".into(), request_meta());

        let message = json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        });
        let encoded =
            serde_json::to_vec(&message).map_err(|error| StdioError::Json(error.to_string()))?;
        if encoded.len() > self.config.max_message_bytes {
            return Err(StdioError::MessageTooLarge(encoded.len()));
        }

        let result = {
            let process = self
                .process
                .as_mut()
                .ok_or_else(|| StdioError::Protocol("MCP process is unavailable".into()))?;
            process
                .stdin
                .write_all(&encoded)
                .and_then(|_| process.stdin.write_all(b"\n"))
                .and_then(|_| process.stdin.flush())
                .map_err(|error| StdioError::Io("write MCP request", error))?;
            receive_response(&process.receiver, request_id, self.config.request_timeout)
        };

        if result.is_err() {
            self.process.take();
        }
        result
    }

    fn discover_inner(&mut self) -> Result<DiscoverySnapshot, StdioError> {
        let discover = self.request("server/discover", Map::new())?;
        let supported_versions = discover
            .get("supportedVersions")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                StdioError::Protocol("server/discover omitted supportedVersions".into())
            })?;

        if !supported_versions
            .iter()
            .any(|version| version.as_str() == Some(MCP_PROTOCOL_REVISION))
        {
            return Err(StdioError::UnsupportedProtocol);
        }

        let reported_server = discover
            .get("_meta")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get(SERVER_INFO_META_KEY))
            .and_then(|value| serde_json::from_value(value.clone()).ok());

        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = BTreeSet::new();

        for _ in 0..MAX_DISCOVERY_PAGES {
            let mut params = Map::new();
            if let Some(cursor_value) = &cursor {
                params.insert("cursor".into(), Value::String(cursor_value.clone()));
            }

            let page = self.request("tools/list", params)?;
            let page_tools = page
                .get("tools")
                .and_then(Value::as_array)
                .ok_or_else(|| StdioError::Protocol("tools/list omitted tools array".into()))?;

            for tool in page_tools {
                let descriptor: ToolDescriptor = serde_json::from_value(tool.clone())
                    .map_err(|error| StdioError::Json(error.to_string()))?;
                tools.push(descriptor);
                if tools.len() > MAX_DISCOVERED_TOOLS {
                    return Err(StdioError::TooManyTools(tools.len()));
                }
            }

            cursor = match page.get("nextCursor") {
                None | Some(Value::Null) => None,
                Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
                Some(_) => {
                    return Err(StdioError::Protocol(
                        "tools/list nextCursor must be a non-empty string or null".into(),
                    ))
                }
            };

            let Some(next) = cursor.as_ref() else {
                return Ok(DiscoverySnapshot {
                    protocol_revision: MCP_PROTOCOL_REVISION.into(),
                    reported_server,
                    tools,
                });
            };
            if !seen_cursors.insert(next.clone()) {
                return Err(StdioError::CursorCycle(next.clone()));
            }
        }

        Err(StdioError::TooManyDiscoveryPages)
    }

    fn call_tool_inner(&mut self, tool_name: &str, arguments: &Value) -> Result<Value, StdioError> {
        let mut params = Map::new();
        params.insert("name".into(), Value::String(tool_name.to_string()));
        params.insert("arguments".into(), arguments.clone());

        let result = self.request("tools/call", params)?;
        if let Some(result_type) = result.get("resultType").and_then(Value::as_str) {
            if result_type != "complete" {
                return Err(StdioError::UnsupportedNonCompleteResult(
                    result_type.to_string(),
                ));
            }
        }
        Ok(result)
    }
}

impl Drop for StdioUpstream {
    fn drop(&mut self) {
        self.close();
    }
}

impl McpUpstream for StdioUpstream {
    fn discover(&mut self) -> Result<DiscoverySnapshot, UpstreamError> {
        self.discover_inner().map_err(Into::into)
    }

    fn call_tool(&mut self, tool_name: &str, arguments: &Value) -> Result<Value, UpstreamError> {
        self.call_tool_inner(tool_name, arguments)
            .map_err(Into::into)
    }
}

struct StdioProcess {
    child: Child,
    stdin: ChildStdin,
    receiver: Receiver<ReaderEvent>,
}

impl Drop for StdioProcess {
    fn drop(&mut self) {
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

enum ReaderEvent {
    Message(Value),
    Error(String),
    Closed,
}

fn spawn_reader(stdout: ChildStdout, max_message_bytes: usize) -> Receiver<ReaderEvent> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            match read_bounded_line(&mut reader, max_message_bytes) {
                Ok(Some(bytes)) if bytes.iter().all(u8::is_ascii_whitespace) => continue,
                Ok(Some(bytes)) => match serde_json::from_slice::<Value>(&bytes) {
                    Ok(message) => {
                        if sender.send(ReaderEvent::Message(message)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(ReaderEvent::Error(format!(
                            "invalid JSON on MCP stdout: {error}"
                        )));
                        break;
                    }
                },
                Ok(None) => {
                    let _ = sender.send(ReaderEvent::Closed);
                    break;
                }
                Err(error) => {
                    let _ = sender.send(ReaderEvent::Error(error.to_string()));
                    break;
                }
            }
        }
    });
    receiver
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_message_bytes: usize,
) -> Result<Option<Vec<u8>>, StdioError> {
    let mut frame = Vec::new();

    loop {
        let available = reader
            .fill_buf()
            .map_err(|error| StdioError::Io("read MCP stdout", error))?;
        if available.is_empty() {
            if frame.is_empty() {
                return Ok(None);
            }
            return Err(StdioError::Protocol(
                "MCP stdout closed with an unterminated JSON-RPC frame".into(),
            ));
        }

        if let Some(position) = available.iter().position(|byte| *byte == b'\n') {
            if frame.len() + position > max_message_bytes {
                return Err(StdioError::MessageTooLarge(frame.len() + position));
            }
            frame.extend_from_slice(&available[..position]);
            reader.consume(position + 1);
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            return Ok(Some(frame));
        }

        if frame.len() + available.len() > max_message_bytes {
            return Err(StdioError::MessageTooLarge(frame.len() + available.len()));
        }
        let consumed = available.len();
        frame.extend_from_slice(available);
        reader.consume(consumed);
    }
}

fn receive_response(
    receiver: &Receiver<ReaderEvent>,
    expected_id: u64,
    timeout: Duration,
) -> Result<Value, StdioError> {
    let mut ignored_notifications = 0_usize;

    loop {
        let event = receiver
            .recv_timeout(timeout)
            .map_err(|error| StdioError::Receive(error.to_string()))?;

        match event {
            ReaderEvent::Error(error) => return Err(StdioError::Protocol(error)),
            ReaderEvent::Closed => return Err(StdioError::ServerClosed),
            ReaderEvent::Message(message) => {
                let object = message.as_object().ok_or_else(|| {
                    StdioError::Protocol("MCP stdout message must be a JSON object".into())
                })?;

                if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                    return Err(StdioError::Protocol(
                        "MCP stdout message is not JSON-RPC 2.0".into(),
                    ));
                }

                if object.contains_key("method") {
                    if object.contains_key("id") {
                        return Err(StdioError::ServerToClientRequest);
                    }
                    ignored_notifications += 1;
                    if ignored_notifications > MAX_IGNORED_NOTIFICATIONS {
                        return Err(StdioError::TooManyNotifications);
                    }
                    continue;
                }

                let response_id = object
                    .get("id")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| StdioError::Protocol("MCP response has invalid id".into()))?;
                if response_id != expected_id {
                    return Err(StdioError::UnexpectedResponseId {
                        expected: expected_id,
                        actual: response_id,
                    });
                }

                if let Some(error) = object.get("error") {
                    return Err(StdioError::JsonRpc(error.to_string()));
                }

                return object
                    .get("result")
                    .cloned()
                    .ok_or_else(|| StdioError::Protocol("MCP response omitted result".into()));
            }
        }
    }
}

fn request_meta() -> Value {
    json!({
        PROTOCOL_VERSION_META_KEY: MCP_PROTOCOL_REVISION,
        CLIENT_CAPABILITIES_META_KEY: {},
        CLIENT_INFO_META_KEY: {
            "name": "Latch",
            "version": env!("CARGO_PKG_VERSION"),
        },
    })
}

fn sha256_file(path: &Path) -> Result<String, StdioError> {
    let mut file = File::open(path).map_err(|error| StdioError::Io("open identity file", error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| StdioError::Io("hash identity file", error))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[derive(Debug, thiserror::Error)]
pub enum StdioError {
    #[error("invalid MCP stdio configuration: {0}")]
    InvalidConfiguration(String),
    #[error("MCP provider identity error: {0}")]
    Provider(#[from] ProviderIdentityError),
    #[error("MCP provider identity material changed: {0}")]
    IdentityMaterialChanged(PathBuf),
    #[error("{0} failed: {1}")]
    Io(&'static str, std::io::Error),
    #[error("MCP JSON error: {0}")]
    Json(String),
    #[error("MCP protocol error: {0}")]
    Protocol(String),
    #[error("MCP server does not support protocol revision 2026-07-28")]
    UnsupportedProtocol,
    #[error("MCP message exceeds configured limit: {0} bytes")]
    MessageTooLarge(usize),
    #[error("MCP server advertised too many tools: {0}")]
    TooManyTools(usize),
    #[error("MCP discovery exceeded page limit")]
    TooManyDiscoveryPages,
    #[error("MCP discovery cursor cycle detected: {0}")]
    CursorCycle(String),
    #[error("MCP stdio receive failed: {0}")]
    Receive(String),
    #[error("MCP stdio server closed before responding")]
    ServerClosed,
    #[error("server-to-client JSON-RPC requests are not supported in MCP 2026-07-28")]
    ServerToClientRequest,
    #[error("too many unsolicited MCP notifications before response")]
    TooManyNotifications,
    #[error("unexpected MCP response id: expected {expected}, got {actual}")]
    UnexpectedResponseId { expected: u64, actual: u64 },
    #[error("MCP JSON-RPC error: {0}")]
    JsonRpc(String),
    #[error("MCP non-complete result is not authorized by this V1 client: {0}")]
    UnsupportedNonCompleteResult(String),
}

impl From<StdioError> for UpstreamError {
    fn from(value: StdioError) -> Self {
        UpstreamError::new(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_meta_pins_modern_protocol_and_no_extra_capabilities() {
        let metadata = request_meta();
        assert_eq!(metadata[PROTOCOL_VERSION_META_KEY], MCP_PROTOCOL_REVISION);
        assert_eq!(metadata[CLIENT_CAPABILITIES_META_KEY], json!({}));
        assert_eq!(metadata[CLIENT_INFO_META_KEY]["name"], "Latch");
    }

    #[test]
    fn bounded_stdio_frame_rejects_oversized_message() {
        let bytes = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"value\":\"too-long\"}}\n";
        let mut reader = Cursor::new(bytes);
        assert!(matches!(
            read_bounded_line(&mut reader, 16),
            Err(StdioError::MessageTooLarge(_))
        ));
    }

    #[test]
    fn bounded_stdio_frame_requires_newline_termination() {
        let mut reader = Cursor::new(b"{\"jsonrpc\":\"2.0\"}");
        assert!(matches!(
            read_bounded_line(&mut reader, 1024),
            Err(StdioError::Protocol(_))
        ));
    }

    #[test]
    fn response_parser_rejects_server_to_client_request() {
        let (sender, receiver) = mpsc::channel();
        sender
            .send(ReaderEvent::Message(json!({
                "jsonrpc":"2.0",
                "id":99,
                "method":"sampling/createMessage",
                "params":{}
            })))
            .expect("send");

        assert!(matches!(
            receive_response(&receiver, 1, Duration::from_millis(50)),
            Err(StdioError::ServerToClientRequest)
        ));
    }

    #[test]
    fn response_parser_accepts_matching_result_after_notification() -> Result<(), StdioError> {
        let (sender, receiver) = mpsc::channel();
        sender
            .send(ReaderEvent::Message(json!({
                "jsonrpc":"2.0",
                "method":"notifications/example",
                "params":{}
            })))
            .expect("notification");
        sender
            .send(ReaderEvent::Message(json!({
                "jsonrpc":"2.0",
                "id":7,
                "result":{"ok":true}
            })))
            .expect("result");

        assert_eq!(
            receive_response(&receiver, 7, Duration::from_millis(50))?,
            json!({"ok":true})
        );
        Ok::<(), StdioError>(())
    }
}

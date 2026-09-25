use latch_audit::{AuditEntryInput, AuditError, AuditEventType, AuditLedger};
use latch_core::{ActionRequest, Effect, ExecutionPermit, Resource};
use processkit::{Command as ProcessCommand, OutputBufferPolicy};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};

pub const RESOURCE_KIND: &str = "shell-command";
pub const OPERATION: &str = "shell.execute";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgumentPolicy {
    Any,
    Exact(Vec<Vec<String>>),
}

impl ArgumentPolicy {
    fn allows(&self, arguments: &[String]) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(allowed) => allowed.iter().any(|candidate| candidate == arguments),
        }
    }

    fn fingerprint_into(&self, hasher: &mut Sha256) {
        match self {
            Self::Any => hash_text(hasher, "any"),
            Self::Exact(sets) => {
                hash_text(hasher, "exact");
                hash_u64(hasher, sets.len() as u64);
                for set in sets {
                    hash_u64(hasher, set.len() as u64);
                    for argument in set {
                        hash_text(hasher, argument);
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandRule {
    id: String,
    executable: PathBuf,
    executable_sha256: String,
    arguments: ArgumentPolicy,
    working_roots: Vec<PathBuf>,
    timeout: Duration,
    max_output_bytes: usize,
    inherited_environment: BTreeSet<String>,
    fixed_environment: BTreeMap<String, String>,
}

impl CommandRule {
    pub fn new(
        id: impl Into<String>,
        executable: impl AsRef<Path>,
        arguments: ArgumentPolicy,
        working_roots: impl IntoIterator<Item = PathBuf>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<Self> {
        let id = id.into();
        validate_command_id(&id)?;

        if timeout.is_zero() {
            return Err(ShellError::InvalidRule(
                "command timeout must be greater than zero".into(),
            ));
        }
        if max_output_bytes == 0 {
            return Err(ShellError::InvalidRule(
                "max_output_bytes must be greater than zero".into(),
            ));
        }

        let executable = fs::canonicalize(executable.as_ref())
            .map_err(|error| ShellError::Io("canonicalize executable", error))?;
        if !executable.is_file() {
            return Err(ShellError::InvalidRule(format!(
                "executable is not a regular file: {}",
                executable.display()
            )));
        }

        let basename = executable
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| ShellError::InvalidRule("executable name is not valid UTF-8".into()))?;
        if forbidden_shell_name(basename) {
            return Err(ShellError::ForbiddenInterpreter(basename.to_string()));
        }

        let mut roots = working_roots
            .into_iter()
            .map(|root| canonical_directory(&root))
            .collect::<Result<Vec<_>>>()?;
        roots.sort();
        roots.dedup();
        if roots.is_empty() {
            return Err(ShellError::InvalidRule(
                "command rule requires at least one working root".into(),
            ));
        }

        let executable_sha256 = sha256_file(&executable)?;

        Ok(Self {
            id,
            executable,
            executable_sha256,
            arguments,
            working_roots: roots,
            timeout,
            max_output_bytes,
            inherited_environment: BTreeSet::new(),
            fixed_environment: BTreeMap::new(),
        })
    }

    pub fn inherit_environment(
        mut self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.inherited_environment
            .extend(names.into_iter().map(Into::into));
        self
    }

    pub fn fixed_environment(
        mut self,
        values: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.fixed_environment.extend(
            values
                .into_iter()
                .map(|(key, value)| (key.into(), value.into())),
        );
        self
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    pub fn working_roots(&self) -> &[PathBuf] {
        &self.working_roots
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"latch-shell-command-rule-v1");
        hash_text(&mut hasher, &self.id);
        hash_path(&mut hasher, &self.executable);
        hash_text(&mut hasher, &self.executable_sha256);
        self.arguments.fingerprint_into(&mut hasher);
        hash_u64(&mut hasher, self.working_roots.len() as u64);
        for root in &self.working_roots {
            hash_path(&mut hasher, root);
        }
        hash_u64(&mut hasher, self.timeout.as_millis() as u64);
        hash_u64(&mut hasher, self.max_output_bytes as u64);
        hash_u64(&mut hasher, self.inherited_environment.len() as u64);
        for name in &self.inherited_environment {
            hash_text(&mut hasher, name);
        }
        hash_u64(&mut hasher, self.fixed_environment.len() as u64);
        for (name, value) in &self.fixed_environment {
            hash_text(&mut hasher, name);
            hash_text(&mut hasher, value);
        }
        hex::encode(hasher.finalize())
    }
}

pub struct ShellAdapter {
    rules: BTreeMap<String, CommandRule>,
    runtime: Arc<Runtime>,
}

impl fmt::Debug for ShellAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShellAdapter")
            .field("command_ids", &self.rules.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ShellAdapter {
    pub fn new(rules: impl IntoIterator<Item = CommandRule>) -> Result<Self> {
        let mut by_id = BTreeMap::new();
        for rule in rules {
            let id = rule.id.clone();
            if by_id.insert(id.clone(), rule).is_some() {
                return Err(ShellError::DuplicateCommand(id));
            }
        }

        if by_id.is_empty() {
            return Err(ShellError::InvalidRule(
                "shell adapter requires at least one command rule".into(),
            ));
        }

        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| ShellError::Runtime(error.to_string()))?;

        Ok(Self {
            rules: by_id,
            runtime: Arc::new(runtime),
        })
    }

    pub fn command_ids(&self) -> impl Iterator<Item = &str> {
        self.rules.keys().map(String::as_str)
    }

    pub fn resource_prefix(&self, command_id: &str, working_root: &Path) -> Result<String> {
        let rule = self.rule(command_id)?;
        let root = canonical_directory(working_root)?;
        if !rule.working_roots.iter().any(|allowed| allowed == &root) {
            return Err(ShellError::WorkingRootNotAllowed(root));
        }
        resource_value(command_id, &root)
    }

    pub fn prepare_line(
        &self,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        working_root: &Path,
        relative_working_dir: &Path,
        line: &str,
    ) -> Result<ActionRequest> {
        let tokens = parse_command_line(line)?;
        let (command_id, arguments) = tokens.split_first().ok_or(ShellError::EmptyCommand)?;

        self.prepare_argv(
            request_id,
            session_id,
            working_root,
            relative_working_dir,
            command_id,
            arguments,
        )
    }

    pub fn prepare_argv(
        &self,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        working_root: &Path,
        relative_working_dir: &Path,
        command_id: &str,
        arguments: &[String],
    ) -> Result<ActionRequest> {
        let rule = self.rule(command_id)?;
        if !rule.arguments.allows(arguments) {
            return Err(ShellError::ArgumentsNotAllowed {
                command_id: command_id.to_string(),
            });
        }

        let root = canonical_directory(working_root)?;
        if !rule.working_roots.iter().any(|allowed| allowed == &root) {
            return Err(ShellError::WorkingRootNotAllowed(root));
        }

        validate_relative_working_dir(relative_working_dir)?;
        let candidate = root.join(relative_working_dir);
        let working_dir = canonical_directory(&candidate)?;
        if !working_dir.starts_with(&root) {
            return Err(ShellError::WorkingDirectoryOutsideRoot(working_dir));
        }

        let working_dir_text = path_text(&working_dir)?;
        let executable_text = path_text(&rule.executable)?;
        let rule_fingerprint = rule.fingerprint();

        Ok(ActionRequest {
            request_id: request_id.into(),
            session_id: session_id.into(),
            operation: OPERATION.into(),
            resource: Resource {
                kind: RESOURCE_KIND.into(),
                value: resource_value(command_id, &working_dir)?,
            },
            arguments: json!({
                "command_id": command_id,
                "argv": arguments,
                "working_dir": working_dir_text,
                "executable": executable_text,
                "executable_sha256": rule.executable_sha256,
                "command_rule_fingerprint": rule_fingerprint,
                "timeout_ms": rule.timeout.as_millis() as u64,
                "max_output_bytes": rule.max_output_bytes as u64,
                "inherited_environment": rule.inherited_environment.iter().collect::<Vec<_>>(),
                "fixed_environment_keys": rule.fixed_environment.keys().collect::<Vec<_>>(),
            }),
        })
    }

    pub fn execute(
        &self,
        permit: &ExecutionPermit,
        ledger: &mut AuditLedger,
        timestamp_unix_ms: i64,
    ) -> Result<ShellOutcome> {
        let request = permit.request();
        if request.operation != OPERATION || request.resource.kind != RESOURCE_KIND {
            return Err(ShellError::InvalidPermit(
                "permit is not for shell.execute".into(),
            ));
        }

        let command_id = request
            .arguments
            .get("command_id")
            .and_then(Value::as_str)
            .ok_or_else(|| ShellError::InvalidPermit("missing command_id".into()))?;
        let rule = self.rule(command_id)?;

        let expected_resource = request
            .arguments
            .get("working_dir")
            .and_then(Value::as_str)
            .ok_or_else(|| ShellError::InvalidPermit("missing working_dir".into()))
            .and_then(|working_dir| {
                resource_value(command_id, Path::new(working_dir))
                    .map_err(|_| ShellError::InvalidPermit("invalid working_dir".into()))
            })?;
        if request.resource.value != expected_resource {
            return Err(ShellError::InvalidPermit(
                "resource does not match command and working directory".into(),
            ));
        }

        let stored_rule_fingerprint = request
            .arguments
            .get("command_rule_fingerprint")
            .and_then(Value::as_str)
            .ok_or_else(|| ShellError::InvalidPermit("missing command_rule_fingerprint".into()))?;
        if stored_rule_fingerprint != rule.fingerprint() {
            return Err(ShellError::CommandRuleChanged(command_id.to_string()));
        }

        let stored_executable = request
            .arguments
            .get("executable")
            .and_then(Value::as_str)
            .ok_or_else(|| ShellError::InvalidPermit("missing executable".into()))?;
        if Path::new(stored_executable) != rule.executable {
            return Err(ShellError::InvalidPermit(
                "permit executable does not match command rule".into(),
            ));
        }

        let stored_executable_hash = request
            .arguments
            .get("executable_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| ShellError::InvalidPermit("missing executable_sha256".into()))?;
        if stored_executable_hash != rule.executable_sha256 {
            return Err(ShellError::InvalidPermit(
                "permit executable hash does not match command rule".into(),
            ));
        }

        let arguments = request_arguments(&request.arguments)?;
        if !rule.arguments.allows(&arguments) {
            return Err(ShellError::ArgumentsNotAllowed {
                command_id: command_id.to_string(),
            });
        }

        let authorized_working_dir = PathBuf::from(
            request
                .arguments
                .get("working_dir")
                .and_then(Value::as_str)
                .ok_or_else(|| ShellError::InvalidPermit("missing working_dir".into()))?,
        );
        let current_working_dir = canonical_directory(&authorized_working_dir)?;
        if current_working_dir != authorized_working_dir {
            return Err(ShellError::WorkingDirectoryChanged {
                authorized: authorized_working_dir,
                current: current_working_dir,
            });
        }
        if !rule
            .working_roots
            .iter()
            .any(|root| current_working_dir.starts_with(root))
        {
            return Err(ShellError::WorkingDirectoryOutsideRoot(current_working_dir));
        }

        let current_executable = fs::canonicalize(&rule.executable)
            .map_err(|error| ShellError::Io("canonicalize executable", error))?;
        if current_executable != rule.executable
            || sha256_file(&current_executable)? != rule.executable_sha256
        {
            return Err(ShellError::ExecutableChanged(rule.executable.clone()));
        }

        ledger.append(audit_entry(
            permit,
            timestamp_unix_ms,
            AuditEventType::ToolForwarded,
            json!({
                "adapter": "shell",
                "command_id": command_id,
                "argv_count": arguments.len(),
                "command_rule_fingerprint": rule.fingerprint(),
            }),
        ))?;

        let process_result = self.run_process(rule, &arguments, &current_working_dir);
        match process_result {
            Ok(outcome) => {
                ledger.append(audit_result_entry(
                    permit,
                    timestamp_unix_ms,
                    command_id,
                    &outcome,
                ))?;
                Ok(outcome)
            }
            Err(error) => {
                ledger.append(audit_entry(
                    permit,
                    timestamp_unix_ms,
                    AuditEventType::ToolResult,
                    json!({
                        "adapter": "shell",
                        "command_id": command_id,
                        "outcome": "error",
                        "error_code": error.code(),
                    }),
                ))?;
                Err(error)
            }
        }
    }

    fn run_process(
        &self,
        rule: &CommandRule,
        arguments: &[String],
        working_dir: &Path,
    ) -> Result<ShellOutcome> {
        let mut command = ProcessCommand::new(&rule.executable)
            .current_dir(working_dir)
            .env_clear()
            .timeout(rule.timeout)
            .output_buffer(OutputBufferPolicy::unbounded().with_max_bytes(rule.max_output_bytes));

        for argument in arguments {
            command = command.arg(argument);
        }

        for name in &rule.inherited_environment {
            if let Some(value) = std::env::var_os(name) {
                command = command.env(name, value);
            }
        }
        for (name, value) in &rule.fixed_environment {
            command = command.env(name, value);
        }

        let result = self
            .runtime
            .block_on(command.output_bytes())
            .map_err(|_| ShellError::ProcessFailure)?;

        Ok(ShellOutcome {
            exit_code: result.code(),
            timed_out: result.timed_out(),
            stdout: result.stdout().clone(),
            stderr: result.stderr().as_bytes().to_vec(),
            truncated: result.truncated(),
            duration_ms: result.duration().as_millis() as u64,
        })
    }

    fn rule(&self, command_id: &str) -> Result<&CommandRule> {
        self.rules
            .get(command_id)
            .ok_or_else(|| ShellError::CommandNotAllowed(command_id.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellOutcome {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    pub duration_ms: u64,
}

#[derive(Debug)]
pub enum ShellError {
    EmptyCommand,
    CompoundExpression(char),
    UnterminatedQuote,
    InvalidRule(String),
    DuplicateCommand(String),
    InvalidCommandId(String),
    ForbiddenInterpreter(String),
    CommandNotAllowed(String),
    ArgumentsNotAllowed {
        command_id: String,
    },
    CommandRuleChanged(String),
    WorkingRootNotAllowed(PathBuf),
    InvalidRelativeWorkingDir(PathBuf),
    WorkingDirectoryOutsideRoot(PathBuf),
    WorkingDirectoryChanged {
        authorized: PathBuf,
        current: PathBuf,
    },
    ExecutableChanged(PathBuf),
    NonUtf8Path(PathBuf),
    InvalidPermit(String),
    ProcessFailure,
    Runtime(String),
    Io(&'static str, std::io::Error),
    Audit(AuditError),
}

impl ShellError {
    fn code(&self) -> &'static str {
        match self {
            Self::EmptyCommand => "EMPTY_COMMAND",
            Self::CompoundExpression(_) => "COMPOUND_EXPRESSION",
            Self::UnterminatedQuote => "UNTERMINATED_QUOTE",
            Self::InvalidRule(_) => "INVALID_RULE",
            Self::DuplicateCommand(_) => "DUPLICATE_COMMAND",
            Self::InvalidCommandId(_) => "INVALID_COMMAND_ID",
            Self::ForbiddenInterpreter(_) => "FORBIDDEN_INTERPRETER",
            Self::CommandNotAllowed(_) => "COMMAND_NOT_ALLOWED",
            Self::ArgumentsNotAllowed { .. } => "ARGUMENTS_NOT_ALLOWED",
            Self::CommandRuleChanged(_) => "COMMAND_RULE_CHANGED",
            Self::WorkingRootNotAllowed(_) => "WORKING_ROOT_NOT_ALLOWED",
            Self::InvalidRelativeWorkingDir(_) => "INVALID_WORKING_DIRECTORY",
            Self::WorkingDirectoryOutsideRoot(_) => "WORKING_DIRECTORY_OUTSIDE_ROOT",
            Self::WorkingDirectoryChanged { .. } => "WORKING_DIRECTORY_CHANGED",
            Self::ExecutableChanged(_) => "EXECUTABLE_CHANGED",
            Self::NonUtf8Path(_) => "NON_UTF8_PATH",
            Self::InvalidPermit(_) => "INVALID_PERMIT",
            Self::ProcessFailure => "PROCESS_FAILURE",
            Self::Runtime(_) => "RUNTIME_FAILURE",
            Self::Io(_, _) => "IO_ERROR",
            Self::Audit(_) => "AUDIT_ERROR",
        }
    }
}

impl fmt::Display for ShellError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommand => write!(formatter, "shell command is empty"),
            Self::CompoundExpression(operator) => write!(
                formatter,
                "compound shell expression is not allowed near operator {operator:?}"
            ),
            Self::UnterminatedQuote => {
                write!(formatter, "shell command contains an unterminated quote")
            }
            Self::InvalidRule(reason) => write!(formatter, "invalid command rule: {reason}"),
            Self::DuplicateCommand(id) => write!(formatter, "duplicate command rule: {id}"),
            Self::InvalidCommandId(id) => write!(formatter, "invalid command id: {id}"),
            Self::ForbiddenInterpreter(name) => {
                write!(
                    formatter,
                    "V1 does not permit registering command shell {name}"
                )
            }
            Self::CommandNotAllowed(id) => write!(formatter, "command is not allowed: {id}"),
            Self::ArgumentsNotAllowed { command_id } => {
                write!(
                    formatter,
                    "arguments are not allowed for command {command_id}"
                )
            }
            Self::CommandRuleChanged(command_id) => {
                write!(
                    formatter,
                    "command rule changed after authorization: {command_id}"
                )
            }
            Self::WorkingRootNotAllowed(path) => {
                write!(formatter, "working root is not allowed: {}", path.display())
            }
            Self::InvalidRelativeWorkingDir(path) => write!(
                formatter,
                "working directory must be relative and may not traverse parents: {}",
                path.display()
            ),
            Self::WorkingDirectoryOutsideRoot(path) => write!(
                formatter,
                "working directory escapes the allowed root: {}",
                path.display()
            ),
            Self::WorkingDirectoryChanged {
                authorized,
                current,
            } => write!(
                formatter,
                "working directory changed after authorization: {} -> {}",
                authorized.display(),
                current.display()
            ),
            Self::ExecutableChanged(path) => write!(
                formatter,
                "command executable changed after rule registration: {}",
                path.display()
            ),
            Self::NonUtf8Path(path) => {
                write!(formatter, "path is not valid UTF-8: {}", path.display())
            }
            Self::InvalidPermit(reason) => write!(formatter, "invalid shell permit: {reason}"),
            Self::ProcessFailure => write!(formatter, "controlled process execution failed"),
            Self::Runtime(reason) => {
                write!(formatter, "failed to initialize process runtime: {reason}")
            }
            Self::Io(operation, error) => write!(formatter, "{operation} failed: {error}"),
            Self::Audit(error) => write!(formatter, "shell audit error: {error}"),
        }
    }
}

impl std::error::Error for ShellError {}

impl From<AuditError> for ShellError {
    fn from(value: AuditError) -> Self {
        Self::Audit(value)
    }
}

pub type Result<T> = std::result::Result<T, ShellError>;

pub fn parse_command_line(line: &str) -> Result<Vec<String>> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut quote = Quote::None;
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut characters = line.chars().peekable();

    while let Some(character) = characters.next() {
        match quote {
            Quote::None => match character {
                '\'' => {
                    quote = Quote::Single;
                    in_token = true;
                }
                '"' => {
                    quote = Quote::Double;
                    in_token = true;
                }
                '&' | '|' | ';' | '<' | '>' | '\u{60}' | '^' | '\n' | '\r' => {
                    return Err(ShellError::CompoundExpression(character));
                }
                '$' if characters.peek() == Some(&'(') => {
                    return Err(ShellError::CompoundExpression('$'));
                }
                character if character.is_whitespace() => {
                    if in_token {
                        tokens.push(std::mem::take(&mut current));
                        in_token = false;
                    }
                }
                _ => {
                    current.push(character);
                    in_token = true;
                }
            },
            Quote::Single => {
                if character == '\'' {
                    quote = Quote::None;
                } else {
                    current.push(character);
                }
            }
            Quote::Double => {
                if character == '"' {
                    quote = Quote::None;
                } else if character == '\\' && characters.peek() == Some(&'"') {
                    characters.next();
                    current.push('"');
                } else {
                    current.push(character);
                }
            }
        }
    }

    if quote != Quote::None {
        return Err(ShellError::UnterminatedQuote);
    }
    if in_token {
        tokens.push(current);
    }
    if tokens.is_empty() {
        return Err(ShellError::EmptyCommand);
    }

    Ok(tokens)
}

fn request_arguments(arguments: &Value) -> Result<Vec<String>> {
    arguments
        .get("argv")
        .and_then(Value::as_array)
        .ok_or_else(|| ShellError::InvalidPermit("missing argv".into()))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| ShellError::InvalidPermit("argv must contain strings".into()))
        })
        .collect()
}

fn audit_entry(
    permit: &ExecutionPermit,
    timestamp_unix_ms: i64,
    event_type: AuditEventType,
    metadata: Value,
) -> AuditEntryInput {
    let request = permit.request();
    AuditEntryInput {
        timestamp_unix_ms,
        event_type,
        session_id: Some(request.session_id.clone()),
        request_id: Some(request.request_id.clone()),
        operation: Some(request.operation.clone()),
        resource_kind: Some(request.resource.kind.clone()),
        resource_value: Some(request.resource.value.clone()),
        decision: Some(Effect::Allow),
        policy_rule: permit.rule_id().map(str::to_string),
        reason: None,
        credential_ref: None,
        metadata,
    }
}

fn audit_result_entry(
    permit: &ExecutionPermit,
    timestamp_unix_ms: i64,
    command_id: &str,
    outcome: &ShellOutcome,
) -> AuditEntryInput {
    audit_entry(
        permit,
        timestamp_unix_ms,
        AuditEventType::ToolResult,
        json!({
            "adapter": "shell",
            "command_id": command_id,
            "outcome": "completed",
            "exit_code": outcome.exit_code,
            "timed_out": outcome.timed_out,
            "truncated": outcome.truncated,
            "duration_ms": outcome.duration_ms,
            "stdout_bytes": outcome.stdout.len(),
            "stderr_bytes": outcome.stderr.len(),
            "stdout_sha256": sha256_bytes(&outcome.stdout),
            "stderr_sha256": sha256_bytes(&outcome.stderr),
        }),
    )
}

fn validate_command_id(id: &str) -> Result<()> {
    if id.is_empty()
        || !id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(ShellError::InvalidCommandId(id.to_string()));
    }
    Ok(())
}

fn forbidden_shell_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "sh" | "sh.exe"
            | "bash"
            | "bash.exe"
            | "dash"
            | "dash.exe"
            | "zsh"
            | "zsh.exe"
            | "fish"
            | "fish.exe"
            | "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
            | "wsl"
            | "wsl.exe"
    )
}

fn canonical_directory(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| ShellError::Io("canonicalize working directory", error))?;
    if canonical.is_dir() {
        Ok(canonical)
    } else {
        Err(ShellError::InvalidRule(format!(
            "working root is not a directory: {}",
            canonical.display()
        )))
    }
}

fn validate_relative_working_dir(path: &Path) -> Result<()> {
    if path.is_absolute() {
        return Err(ShellError::InvalidRelativeWorkingDir(path.to_path_buf()));
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(ShellError::InvalidRelativeWorkingDir(path.to_path_buf()));
        }
    }
    Ok(())
}

fn resource_value(command_id: &str, working_dir: &Path) -> Result<String> {
    Ok(format!("{command_id}#{}", path_text(working_dir)?))
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| ShellError::NonUtf8Path(path.to_path_buf()))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).map_err(|error| ShellError::Io("open executable for hashing", error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| ShellError::Io("hash executable", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hash_u64(hasher, value.len() as u64);
    hasher.update(value.as_bytes());
}

fn hash_path(hasher: &mut Sha256, path: &Path) {
    hash_text(hasher, &path.to_string_lossy());
}

#[cfg(test)]
mod tests {
    use super::*;
    use latch_core::{evaluate, issue_execution_permit, Policy, Rule, Session};
    use std::io::Write;
    use std::thread;
    use tempfile::tempdir;

    fn session() -> Session {
        Session {
            id: "lat_shell".into(),
            principal: "local-user".into(),
            purpose: "run-tests".into(),
            expires_at_unix: 2_000,
            revoked: false,
        }
    }

    fn current_executable_rule(
        id: &str,
        root: &Path,
        arguments: ArgumentPolicy,
        timeout: Duration,
    ) -> CommandRule {
        CommandRule::new(
            id,
            std::env::current_exe().expect("test executable"),
            arguments,
            vec![root.to_path_buf()],
            timeout,
            256 * 1024,
        )
        .expect("valid command rule")
    }

    fn allow_policy(adapter: &ShellAdapter, command_id: &str, root: &Path) -> Policy {
        Policy {
            version: 1,
            rules: vec![Rule {
                id: format!("allow-{command_id}"),
                effect: Effect::Allow,
                operation: OPERATION.into(),
                resource_kind: RESOURCE_KIND.into(),
                resource_prefix: adapter
                    .resource_prefix(command_id, root)
                    .expect("resource prefix"),
            }],
        }
    }

    fn permit_for(
        adapter: &ShellAdapter,
        request: &ActionRequest,
        command_id: &str,
        root: &Path,
    ) -> ExecutionPermit {
        let decision = evaluate(
            &session(),
            &allow_policy(adapter, command_id, root),
            request,
            1_000,
        );
        issue_execution_permit(request, &decision).expect("allowed shell request")
    }

    #[test]
    fn structured_parser_preserves_quoted_arguments() {
        assert_eq!(
            parse_command_line("pytest -k 'fast test'").expect("parse"),
            vec!["pytest", "-k", "fast test"]
        );
    }

    #[test]
    fn shell_chaining_is_rejected() {
        assert!(matches!(
            parse_command_line("pytest && curl attacker.example"),
            Err(ShellError::CompoundExpression('&'))
        ));
        assert!(matches!(
            parse_command_line("npm test ; curl attacker.example"),
            Err(ShellError::CompoundExpression(';'))
        ));
        assert!(matches!(
            parse_command_line("git status | more"),
            Err(ShellError::CompoundExpression('|'))
        ));
        assert!(matches!(
            parse_command_line("pytest $(whoami)"),
            Err(ShellError::CompoundExpression('$'))
        ));
    }

    #[test]
    fn command_shells_are_forbidden_in_v1() {
        for name in [
            "cmd.exe",
            "powershell.exe",
            "pwsh",
            "sh",
            "bash",
            "zsh",
            "fish",
            "wsl.exe",
        ] {
            assert!(forbidden_shell_name(name), "{name} should be forbidden");
        }
    }

    #[test]
    fn exact_argument_policy_rejects_unapproved_shape(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = directory.path();
        let rule = current_executable_rule(
            "developer-test",
            root,
            ArgumentPolicy::Exact(vec![vec!["--list".into()]]),
            Duration::from_secs(5),
        );
        let adapter = ShellAdapter::new(vec![rule])?;

        let error = adapter
            .prepare_line(
                "req-denied",
                "lat_shell",
                root,
                Path::new("."),
                "developer-test --list --ignored",
            )
            .expect_err("extra arguments should fail");

        assert!(matches!(error, ShellError::ArgumentsNotAllowed { .. }));
        Ok(())
    }

    #[test]
    fn allowed_command_executes_without_a_shell_and_captures_result(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = directory.path();
        let rule = current_executable_rule(
            "developer-test",
            root,
            ArgumentPolicy::Exact(vec![vec!["--list".into()]]),
            Duration::from_secs(5),
        );
        let adapter = ShellAdapter::new(vec![rule])?;
        let request = adapter.prepare_line(
            "req-run",
            "lat_shell",
            root,
            Path::new("."),
            "developer-test --list",
        )?;

        let policy = allow_policy(&adapter, "developer-test", root);
        let decision = evaluate(&session(), &policy, &request, 1_000);
        let permit = issue_execution_permit(&request, &decision)?;
        let mut ledger = AuditLedger::in_memory()?;
        ledger.record_authorization(1_000_000, &session(), &request, &decision)?;

        let outcome = adapter.execute(&permit, &mut ledger, 1_000_001)?;

        assert_eq!(outcome.exit_code, Some(0));
        assert!(!outcome.timed_out);
        assert!(!outcome.stdout.is_empty());
        let entries = ledger.entries()?;
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[2].event_type, "TOOL_FORWARDED");
        assert_eq!(entries[3].event_type, "TOOL_RESULT");
        assert!(ledger.verify()?.valid);
        Ok(())
    }

    #[test]
    fn changed_executable_is_rejected_before_spawn(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = directory.path();
        let copy_name = if cfg!(windows) {
            "copied-test.exe"
        } else {
            "copied-test"
        };
        let copied = root.join(copy_name);
        fs::copy(std::env::current_exe()?, &copied)?;

        let rule = CommandRule::new(
            "copied-test",
            &copied,
            ArgumentPolicy::Exact(vec![vec!["--list".into()]]),
            vec![root.to_path_buf()],
            Duration::from_secs(5),
            256 * 1024,
        )?;
        let adapter = ShellAdapter::new(vec![rule])?;
        let request = adapter.prepare_line(
            "req-changed",
            "lat_shell",
            root,
            Path::new("."),
            "copied-test --list",
        )?;
        let permit = permit_for(&adapter, &request, "copied-test", root);

        let mut file = fs::OpenOptions::new().write(true).open(&copied)?;
        file.write_all(b"LATCH")?;
        file.flush()?;

        let mut ledger = AuditLedger::in_memory()?;
        let error = adapter
            .execute(&permit, &mut ledger, 1_000_001)
            .expect_err("modified executable should fail closed");

        assert!(matches!(error, ShellError::ExecutableChanged(_)));
        Ok(())
    }

    #[test]
    fn timeout_child_helper() {
        if std::env::var_os("LATCH_TIMEOUT_CHILD").is_some() {
            thread::sleep(Duration::from_millis(750));
        }
    }

    #[test]
    fn timeout_terminates_controlled_process() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let root = directory.path();
        let args = vec![
            "--exact".into(),
            "tests::timeout_child_helper".into(),
            "--nocapture".into(),
        ];
        let rule = current_executable_rule(
            "slow-test",
            root,
            ArgumentPolicy::Exact(vec![args.clone()]),
            Duration::from_millis(100),
        )
        .fixed_environment([("LATCH_TIMEOUT_CHILD", "1")]);
        let adapter = ShellAdapter::new(vec![rule])?;
        let request = adapter.prepare_argv(
            "req-timeout",
            "lat_shell",
            root,
            Path::new("."),
            "slow-test",
            &args,
        )?;
        let permit = permit_for(&adapter, &request, "slow-test", root);
        let mut ledger = AuditLedger::in_memory()?;

        let outcome = adapter.execute(&permit, &mut ledger, 1_000_001)?;

        assert!(outcome.timed_out);
        assert_eq!(outcome.exit_code, None);
        assert!(outcome.duration_ms < 700);
        Ok(())
    }

    #[test]
    fn working_directory_parent_escape_is_rejected(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = directory.path();
        let rule = current_executable_rule(
            "developer-test",
            root,
            ArgumentPolicy::Any,
            Duration::from_secs(5),
        );
        let adapter = ShellAdapter::new(vec![rule])?;

        let error = adapter
            .prepare_line(
                "req-escape",
                "lat_shell",
                root,
                Path::new("../outside"),
                "developer-test --list",
            )
            .expect_err("working directory traversal should fail");

        assert!(matches!(error, ShellError::InvalidRelativeWorkingDir(_)));
        Ok(())
    }
}

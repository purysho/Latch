use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use latch_audit::{AuditEntryInput, AuditError, AuditEventType, AuditLedger};
use latch_core::{ActionRequest, Effect, ExecutionPermit, Resource};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub const RESOURCE_KIND: &str = "filesystem";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsOperation {
    Read,
    Write,
    Create,
    Delete,
}

impl FsOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "filesystem.read",
            Self::Write => "filesystem.write",
            Self::Create => "filesystem.create",
            Self::Delete => "filesystem.delete",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "filesystem.read" => Some(Self::Read),
            "filesystem.write" => Some(Self::Write),
            "filesystem.create" => Some(Self::Create),
            "filesystem.delete" => Some(Self::Delete),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsOutcome {
    Read(Vec<u8>),
    Written { bytes: usize },
    Created { bytes: usize },
    Deleted,
}

#[derive(Debug)]
pub enum FsError {
    NoRoots,
    RootNotAllowed(PathBuf),
    InvalidRelativePath(PathBuf),
    NonUtf8Path(PathBuf),
    PathOutsideRoot(PathBuf),
    ProtectedPath(PathBuf),
    LeafSymlink(PathBuf),
    TargetNotFound(PathBuf),
    TargetAlreadyExists(PathBuf),
    TargetNotFile(PathBuf),
    InvalidPermit(String),
    InvalidArguments(String),
    PathChangedAfterAuthorization {
        authorized: PathBuf,
        current: PathBuf,
    },
    Io(std::io::Error),
    Audit(AuditError),
}

impl FsError {
    fn code(&self) -> &'static str {
        match self {
            Self::NoRoots => "NO_ROOTS",
            Self::RootNotAllowed(_) => "ROOT_NOT_ALLOWED",
            Self::InvalidRelativePath(_) => "INVALID_RELATIVE_PATH",
            Self::NonUtf8Path(_) => "NON_UTF8_PATH",
            Self::PathOutsideRoot(_) => "PATH_OUTSIDE_ROOT",
            Self::ProtectedPath(_) => "PROTECTED_PATH",
            Self::LeafSymlink(_) => "LEAF_SYMLINK",
            Self::TargetNotFound(_) => "TARGET_NOT_FOUND",
            Self::TargetAlreadyExists(_) => "TARGET_ALREADY_EXISTS",
            Self::TargetNotFile(_) => "TARGET_NOT_FILE",
            Self::InvalidPermit(_) => "INVALID_PERMIT",
            Self::InvalidArguments(_) => "INVALID_ARGUMENTS",
            Self::PathChangedAfterAuthorization { .. } => "PATH_CHANGED",
            Self::Io(_) => "IO_ERROR",
            Self::Audit(_) => "AUDIT_ERROR",
        }
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoots => write!(formatter, "filesystem adapter requires at least one root"),
            Self::RootNotAllowed(path) => {
                write!(
                    formatter,
                    "filesystem root is not configured: {}",
                    path.display()
                )
            }
            Self::InvalidRelativePath(path) => write!(
                formatter,
                "filesystem path must be relative and may not contain parent traversal: {}",
                path.display()
            ),
            Self::NonUtf8Path(path) => {
                write!(
                    formatter,
                    "filesystem path is not valid UTF-8: {}",
                    path.display()
                )
            }
            Self::PathOutsideRoot(path) => {
                write!(
                    formatter,
                    "filesystem target escapes configured root: {}",
                    path.display()
                )
            }
            Self::ProtectedPath(path) => {
                write!(
                    formatter,
                    "filesystem target is protected: {}",
                    path.display()
                )
            }
            Self::LeafSymlink(path) => {
                write!(
                    formatter,
                    "filesystem leaf symlink is not executable: {}",
                    path.display()
                )
            }
            Self::TargetNotFound(path) => {
                write!(
                    formatter,
                    "filesystem target does not exist: {}",
                    path.display()
                )
            }
            Self::TargetAlreadyExists(path) => {
                write!(
                    formatter,
                    "filesystem create target already exists: {}",
                    path.display()
                )
            }
            Self::TargetNotFile(path) => {
                write!(
                    formatter,
                    "filesystem target is not a regular file: {}",
                    path.display()
                )
            }
            Self::InvalidPermit(reason) => write!(formatter, "invalid filesystem permit: {reason}"),
            Self::InvalidArguments(reason) => {
                write!(formatter, "invalid filesystem request arguments: {reason}")
            }
            Self::PathChangedAfterAuthorization {
                authorized,
                current,
            } => write!(
                formatter,
                "filesystem target changed after authorization: {} -> {}",
                authorized.display(),
                current.display()
            ),
            Self::Io(error) => write!(formatter, "filesystem I/O error: {error}"),
            Self::Audit(error) => write!(formatter, "filesystem audit error: {error}"),
        }
    }
}

impl std::error::Error for FsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Audit(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FsError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<AuditError> for FsError {
    fn from(value: AuditError) -> Self {
        Self::Audit(value)
    }
}

pub type Result<T> = std::result::Result<T, FsError>;

#[derive(Debug, Clone)]
pub struct FilesystemAdapter {
    roots: Vec<PathBuf>,
    protected_paths: Vec<PathBuf>,
}

impl FilesystemAdapter {
    pub fn new(
        roots: impl IntoIterator<Item = PathBuf>,
        protected_paths: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self> {
        let roots = roots
            .into_iter()
            .map(|root| canonical_existing_directory(&root))
            .collect::<Result<Vec<_>>>()?;

        if roots.is_empty() {
            return Err(FsError::NoRoots);
        }

        let protected_paths = protected_paths
            .into_iter()
            .map(|path| canonical_candidate(&path))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            roots,
            protected_paths,
        })
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    pub fn protected_paths(&self) -> &[PathBuf] {
        &self.protected_paths
    }

    pub fn prepare_read(
        &self,
        root: &Path,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        relative_path: &Path,
    ) -> Result<ActionRequest> {
        self.prepare_existing(
            root,
            request_id.into(),
            session_id.into(),
            FsOperation::Read,
            relative_path,
            json!({}),
        )
    }

    pub fn prepare_write(
        &self,
        root: &Path,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        relative_path: &Path,
        contents: &[u8],
    ) -> Result<ActionRequest> {
        self.prepare_existing(
            root,
            request_id.into(),
            session_id.into(),
            FsOperation::Write,
            relative_path,
            encoded_contents(contents),
        )
    }

    pub fn prepare_delete(
        &self,
        root: &Path,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        relative_path: &Path,
    ) -> Result<ActionRequest> {
        self.prepare_existing(
            root,
            request_id.into(),
            session_id.into(),
            FsOperation::Delete,
            relative_path,
            json!({}),
        )
    }

    pub fn prepare_create(
        &self,
        root: &Path,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        relative_path: &Path,
        contents: &[u8],
    ) -> Result<ActionRequest> {
        validate_relative_path(relative_path)?;
        let root = self.resolve_root(root)?;
        let candidate = root.join(relative_path);

        if fs::symlink_metadata(&candidate).is_ok() {
            return Err(FsError::TargetAlreadyExists(candidate));
        }

        let parent = candidate
            .parent()
            .ok_or_else(|| FsError::InvalidRelativePath(relative_path.to_path_buf()))?;
        let canonical_parent =
            fs::canonicalize(parent).map_err(|error| map_not_found(error, parent.to_path_buf()))?;
        self.ensure_within_roots(&canonical_parent)?;

        let filename = candidate
            .file_name()
            .ok_or_else(|| FsError::InvalidRelativePath(relative_path.to_path_buf()))?;
        let canonical_target = canonical_parent.join(filename);
        self.ensure_within_roots(&canonical_target)?;
        self.ensure_not_protected(&canonical_target)?;

        request_from_path(
            request_id.into(),
            session_id.into(),
            FsOperation::Create,
            &canonical_target,
            encoded_contents(contents),
        )
    }

    pub fn execute(
        &self,
        permit: &ExecutionPermit,
        ledger: &mut AuditLedger,
        timestamp_unix_ms: i64,
    ) -> Result<FsOutcome> {
        let request = permit.request();
        if request.resource.kind != RESOURCE_KIND {
            return Err(FsError::InvalidPermit(format!(
                "resource kind {} is not filesystem",
                request.resource.kind
            )));
        }

        let operation = FsOperation::from_str(&request.operation).ok_or_else(|| {
            FsError::InvalidPermit(format!("unsupported operation {}", request.operation))
        })?;

        let authorized_path = PathBuf::from(&request.resource.value);
        self.ensure_within_roots(&authorized_path)?;
        self.ensure_not_protected(&authorized_path)?;

        match operation {
            FsOperation::Read => {
                let current = self.revalidate_existing(&authorized_path)?;
                self.ensure_same_path(&authorized_path, &current)?;
                self.audit_forwarded(permit, ledger, timestamp_unix_ms)?;
                let outcome = self.read_file(&current);
                self.audit_result(permit, ledger, timestamp_unix_ms, &outcome)?;
                outcome
            }
            FsOperation::Write => {
                let current = self.revalidate_existing(&authorized_path)?;
                self.ensure_same_path(&authorized_path, &current)?;
                let contents = decode_contents(&request.arguments)?;
                self.audit_forwarded(permit, ledger, timestamp_unix_ms)?;
                let outcome = self.write_file(&current, &contents);
                self.audit_result(permit, ledger, timestamp_unix_ms, &outcome)?;
                outcome
            }
            FsOperation::Create => {
                let current = self.revalidate_create(&authorized_path)?;
                self.ensure_same_path(&authorized_path, &current)?;
                let contents = decode_contents(&request.arguments)?;
                self.audit_forwarded(permit, ledger, timestamp_unix_ms)?;
                let outcome = self.create_file(&current, &contents);
                self.audit_result(permit, ledger, timestamp_unix_ms, &outcome)?;
                outcome
            }
            FsOperation::Delete => {
                let current = self.revalidate_existing(&authorized_path)?;
                self.ensure_same_path(&authorized_path, &current)?;
                self.audit_forwarded(permit, ledger, timestamp_unix_ms)?;
                let outcome = self.delete_file(&current);
                self.audit_result(permit, ledger, timestamp_unix_ms, &outcome)?;
                outcome
            }
        }
    }

    fn prepare_existing(
        &self,
        root: &Path,
        request_id: String,
        session_id: String,
        operation: FsOperation,
        relative_path: &Path,
        arguments: Value,
    ) -> Result<ActionRequest> {
        validate_relative_path(relative_path)?;
        let root = self.resolve_root(root)?;
        let candidate = root.join(relative_path);
        reject_leaf_symlink(&candidate)?;

        let canonical_target = fs::canonicalize(&candidate)
            .map_err(|error| map_not_found(error, candidate.clone()))?;
        self.ensure_within_roots(&canonical_target)?;
        self.ensure_not_protected(&canonical_target)?;
        ensure_regular_file(&canonical_target)?;

        request_from_path(
            request_id,
            session_id,
            operation,
            &canonical_target,
            arguments,
        )
    }

    fn resolve_root(&self, root: &Path) -> Result<PathBuf> {
        let canonical = canonical_existing_directory(root)?;
        if self.roots.iter().any(|allowed| allowed == &canonical) {
            Ok(canonical)
        } else {
            Err(FsError::RootNotAllowed(canonical))
        }
    }

    fn ensure_within_roots(&self, path: &Path) -> Result<()> {
        if self.roots.iter().any(|root| path.starts_with(root)) {
            Ok(())
        } else {
            Err(FsError::PathOutsideRoot(path.to_path_buf()))
        }
    }

    fn ensure_not_protected(&self, path: &Path) -> Result<()> {
        if self
            .protected_paths
            .iter()
            .any(|protected| path == protected || path.starts_with(protected))
        {
            Err(FsError::ProtectedPath(path.to_path_buf()))
        } else {
            Ok(())
        }
    }

    fn ensure_same_path(&self, authorized: &Path, current: &Path) -> Result<()> {
        if authorized == current {
            Ok(())
        } else {
            Err(FsError::PathChangedAfterAuthorization {
                authorized: authorized.to_path_buf(),
                current: current.to_path_buf(),
            })
        }
    }

    fn revalidate_existing(&self, path: &Path) -> Result<PathBuf> {
        reject_leaf_symlink(path)?;
        let canonical =
            fs::canonicalize(path).map_err(|error| map_not_found(error, path.to_path_buf()))?;
        self.ensure_within_roots(&canonical)?;
        self.ensure_not_protected(&canonical)?;
        ensure_regular_file(&canonical)?;
        Ok(canonical)
    }

    fn revalidate_create(&self, path: &Path) -> Result<PathBuf> {
        if fs::symlink_metadata(path).is_ok() {
            return Err(FsError::TargetAlreadyExists(path.to_path_buf()));
        }

        let parent = path
            .parent()
            .ok_or_else(|| FsError::InvalidRelativePath(path.to_path_buf()))?;
        let canonical_parent =
            fs::canonicalize(parent).map_err(|error| map_not_found(error, parent.to_path_buf()))?;
        self.ensure_within_roots(&canonical_parent)?;
        self.ensure_not_protected(&canonical_parent)?;

        let filename = path
            .file_name()
            .ok_or_else(|| FsError::InvalidRelativePath(path.to_path_buf()))?;
        let current = canonical_parent.join(filename);
        self.ensure_within_roots(&current)?;
        self.ensure_not_protected(&current)?;
        Ok(current)
    }

    fn read_file(&self, path: &Path) -> Result<FsOutcome> {
        let mut file = File::open(path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        Ok(FsOutcome::Read(contents))
    }

    fn write_file(&self, path: &Path, contents: &[u8]) -> Result<FsOutcome> {
        let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        Ok(FsOutcome::Written {
            bytes: contents.len(),
        })
    }

    fn create_file(&self, path: &Path, contents: &[u8]) -> Result<FsOutcome> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        Ok(FsOutcome::Created {
            bytes: contents.len(),
        })
    }

    fn delete_file(&self, path: &Path) -> Result<FsOutcome> {
        fs::remove_file(path)?;
        Ok(FsOutcome::Deleted)
    }

    fn audit_forwarded(
        &self,
        permit: &ExecutionPermit,
        ledger: &mut AuditLedger,
        timestamp_unix_ms: i64,
    ) -> Result<()> {
        ledger.append(audit_entry(
            permit,
            timestamp_unix_ms,
            AuditEventType::ToolForwarded,
            json!({"adapter": "filesystem"}),
            None,
        ))?;
        Ok(())
    }

    fn audit_result(
        &self,
        permit: &ExecutionPermit,
        ledger: &mut AuditLedger,
        timestamp_unix_ms: i64,
        outcome: &Result<FsOutcome>,
    ) -> Result<()> {
        let metadata = match outcome {
            Ok(FsOutcome::Read(contents)) => {
                json!({"adapter": "filesystem", "outcome": "success", "bytes": contents.len()})
            }
            Ok(FsOutcome::Written { bytes }) | Ok(FsOutcome::Created { bytes }) => {
                json!({"adapter": "filesystem", "outcome": "success", "bytes": bytes})
            }
            Ok(FsOutcome::Deleted) => {
                json!({"adapter": "filesystem", "outcome": "success"})
            }
            Err(error) => json!({
                "adapter": "filesystem",
                "outcome": "error",
                "error_code": error.code()
            }),
        };

        ledger.append(audit_entry(
            permit,
            timestamp_unix_ms,
            AuditEventType::ToolResult,
            metadata,
            None,
        ))?;
        Ok(())
    }
}

fn audit_entry(
    permit: &ExecutionPermit,
    timestamp_unix_ms: i64,
    event_type: AuditEventType,
    metadata: Value,
    reason: Option<String>,
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
        reason,
        credential_ref: None,
        metadata,
    }
}

fn request_from_path(
    request_id: String,
    session_id: String,
    operation: FsOperation,
    canonical_path: &Path,
    arguments: Value,
) -> Result<ActionRequest> {
    let value = canonical_path
        .to_str()
        .ok_or_else(|| FsError::NonUtf8Path(canonical_path.to_path_buf()))?
        .to_string();

    Ok(ActionRequest {
        request_id,
        session_id,
        operation: operation.as_str().to_string(),
        resource: Resource {
            kind: RESOURCE_KIND.to_string(),
            value,
        },
        arguments,
    })
}

fn encoded_contents(contents: &[u8]) -> Value {
    json!({
        "content_b64": BASE64.encode(contents),
        "content_sha256": sha256_bytes(contents)
    })
}

fn decode_contents(arguments: &Value) -> Result<Vec<u8>> {
    let encoded = arguments
        .get("content_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| FsError::InvalidArguments("missing content_b64".into()))?;
    let expected_hash = arguments
        .get("content_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| FsError::InvalidArguments("missing content_sha256".into()))?;

    let contents = BASE64
        .decode(encoded)
        .map_err(|_| FsError::InvalidArguments("content_b64 is not valid base64".into()))?;

    if sha256_bytes(&contents) != expected_hash {
        return Err(FsError::InvalidArguments(
            "content_sha256 does not match decoded content".into(),
        ));
    }

    Ok(contents)
}

fn sha256_bytes(contents: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(contents);
    hex::encode(hasher.finalize())
}

fn canonical_existing_directory(path: &Path) -> Result<PathBuf> {
    let canonical =
        fs::canonicalize(path).map_err(|error| map_not_found(error, path.to_path_buf()))?;
    if canonical.is_dir() {
        Ok(canonical)
    } else {
        Err(FsError::RootNotAllowed(canonical))
    }
}

fn canonical_candidate(path: &Path) -> Result<PathBuf> {
    if fs::symlink_metadata(path).is_ok() {
        return fs::canonicalize(path).map_err(FsError::Io);
    }

    let mut missing = Vec::new();
    let mut cursor = path;

    loop {
        if fs::symlink_metadata(cursor).is_ok() {
            let mut canonical = fs::canonicalize(cursor)?;
            for component in missing.iter().rev() {
                canonical.push(component);
            }
            return Ok(canonical);
        }

        let file_name = cursor
            .file_name()
            .ok_or_else(|| FsError::TargetNotFound(path.to_path_buf()))?;
        missing.push(file_name.to_os_string());
        cursor = cursor
            .parent()
            .ok_or_else(|| FsError::TargetNotFound(path.to_path_buf()))?;
    }
}

fn validate_relative_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(FsError::InvalidRelativePath(path.to_path_buf()));
    }

    for component in path.components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FsError::InvalidRelativePath(path.to_path_buf()));
            }
            Component::CurDir | Component::Normal(_) => {}
        }
    }

    Ok(())
}

fn reject_leaf_symlink(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| map_not_found(error, path.to_path_buf()))?;
    if metadata.file_type().is_symlink() {
        Err(FsError::LeafSymlink(path.to_path_buf()))
    } else {
        Ok(())
    }
}

fn ensure_regular_file(path: &Path) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(FsError::TargetNotFile(path.to_path_buf()))
    }
}

fn map_not_found(error: std::io::Error, path: PathBuf) -> FsError {
    if error.kind() == std::io::ErrorKind::NotFound {
        FsError::TargetNotFound(path)
    } else {
        FsError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use latch_core::{evaluate, issue_execution_permit, Decision, Policy, Rule, Session};
    use tempfile::tempdir;

    fn session() -> Session {
        Session {
            id: "lat_fs".into(),
            principal: "local-user".into(),
            purpose: "filesystem-test".into(),
            expires_at_unix: 2_000,
            revoked: false,
        }
    }

    fn allow_policy(root: &Path, operation: FsOperation) -> Policy {
        let canonical_root = fs::canonicalize(root).expect("test root should canonicalize");
        Policy {
            version: 1,
            rules: vec![Rule {
                id: format!("allow-{}", operation.as_str()),
                effect: Effect::Allow,
                operation: operation.as_str().into(),
                resource_kind: RESOURCE_KIND.into(),
                resource_prefix: canonical_root.to_string_lossy().into_owned(),
            }],
        }
    }

    fn permit_for(request: &ActionRequest, operation: FsOperation, root: &Path) -> ExecutionPermit {
        let decision = evaluate(&session(), &allow_policy(root, operation), request, 1_000);
        issue_execution_permit(request, &decision).expect("allow decision should issue permit")
    }

    fn record_decision(
        ledger: &mut AuditLedger,
        request: &ActionRequest,
        operation: FsOperation,
        root: &Path,
    ) -> Decision {
        let decision = evaluate(&session(), &allow_policy(root, operation), request, 1_000);
        ledger
            .record_authorization(1_000_000, &session(), request, &decision)
            .expect("authorization should be audited");
        decision
    }

    #[test]
    fn read_executes_only_from_an_allow_permit(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = directory.path().join("workspace");
        fs::create_dir(&root)?;
        fs::write(root.join("notes.txt"), b"hello")?;

        let adapter = FilesystemAdapter::new(vec![root.clone()], Vec::new())?;
        let request = adapter.prepare_read(&root, "req-read", "lat_fs", Path::new("notes.txt"))?;
        let mut ledger = AuditLedger::in_memory()?;
        let decision = record_decision(&mut ledger, &request, FsOperation::Read, &root);
        let permit = issue_execution_permit(&request, &decision)?;

        assert_eq!(
            adapter.execute(&permit, &mut ledger, 1_000_001)?,
            FsOutcome::Read(b"hello".to_vec())
        );

        let entries = ledger.entries()?;
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[2].event_type, "TOOL_FORWARDED");
        assert_eq!(entries[3].event_type, "TOOL_RESULT");
        assert!(ledger.verify()?.valid);
        Ok(())
    }

    #[test]
    fn write_content_is_bound_into_the_authorized_request(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = directory.path().join("workspace");
        fs::create_dir(&root)?;
        fs::write(root.join("notes.txt"), b"before")?;

        let adapter = FilesystemAdapter::new(vec![root.clone()], Vec::new())?;
        let request = adapter.prepare_write(
            &root,
            "req-write",
            "lat_fs",
            Path::new("notes.txt"),
            b"after",
        )?;
        let permit = permit_for(&request, FsOperation::Write, &root);
        let mut ledger = AuditLedger::in_memory()?;

        assert_eq!(
            adapter.execute(&permit, &mut ledger, 1_000_001)?,
            FsOutcome::Written { bytes: 5 }
        );
        assert_eq!(fs::read(root.join("notes.txt"))?, b"after");
        Ok(())
    }

    #[test]
    fn create_and_delete_are_distinct_operations(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = directory.path().join("workspace");
        fs::create_dir(&root)?;
        let adapter = FilesystemAdapter::new(vec![root.clone()], Vec::new())?;

        let create =
            adapter.prepare_create(&root, "req-create", "lat_fs", Path::new("new.txt"), b"new")?;
        let create_permit = permit_for(&create, FsOperation::Create, &root);
        let mut ledger = AuditLedger::in_memory()?;
        assert_eq!(
            adapter.execute(&create_permit, &mut ledger, 1_000_001)?,
            FsOutcome::Created { bytes: 3 }
        );

        let delete = adapter.prepare_delete(&root, "req-delete", "lat_fs", Path::new("new.txt"))?;
        let delete_permit = permit_for(&delete, FsOperation::Delete, &root);
        assert_eq!(
            adapter.execute(&delete_permit, &mut ledger, 1_000_002)?,
            FsOutcome::Deleted
        );
        assert!(!root.join("new.txt").exists());
        Ok(())
    }

    #[test]
    fn parent_traversal_is_rejected_before_policy_evaluation(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = directory.path().join("workspace");
        fs::create_dir(&root)?;
        let adapter = FilesystemAdapter::new(vec![root.clone()], Vec::new())?;

        let error = adapter
            .prepare_read(&root, "req", "lat_fs", Path::new("../outside.txt"))
            .expect_err("parent traversal must be rejected");

        assert!(matches!(error, FsError::InvalidRelativePath(_)));
        Ok(())
    }

    #[test]
    fn nonexistent_protected_path_cannot_be_created(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = directory.path().join("workspace");
        fs::create_dir(&root)?;
        let protected = root.join(".env");
        let adapter = FilesystemAdapter::new(vec![root.clone()], vec![protected.clone()])?;

        let error = adapter
            .prepare_create(&root, "req", "lat_fs", Path::new(".env"), b"secret")
            .expect_err("protected path must be blocked");

        assert!(matches!(error, FsError::ProtectedPath(_)));
        Ok(())
    }

    #[test]
    fn protected_path_is_rechecked_at_execution_even_with_allow_permit(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = directory.path().join("workspace");
        fs::create_dir(&root)?;
        let protected = root.join("protected.txt");
        fs::write(&protected, b"secret")?;

        let adapter = FilesystemAdapter::new(vec![root.clone()], vec![protected.clone()])?;
        let canonical = fs::canonicalize(&protected)?;
        let request = ActionRequest {
            request_id: "req-protected".into(),
            session_id: "lat_fs".into(),
            operation: FsOperation::Read.as_str().into(),
            resource: Resource {
                kind: RESOURCE_KIND.into(),
                value: canonical.to_string_lossy().into_owned(),
            },
            arguments: json!({}),
        };
        let permit = permit_for(&request, FsOperation::Read, &root);
        let mut ledger = AuditLedger::in_memory()?;

        let error = adapter
            .execute(&permit, &mut ledger, 1_000_001)
            .expect_err("adapter must enforce protected paths defensively");
        assert!(matches!(error, FsError::ProtectedPath(_)));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn replacing_an_authorized_file_with_a_symlink_fails_closed(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = directory.path().join("workspace");
        let outside = directory.path().join("outside.txt");
        fs::create_dir(&root)?;
        fs::write(root.join("target.txt"), b"inside")?;
        fs::write(&outside, b"outside")?;

        let adapter = FilesystemAdapter::new(vec![root.clone()], Vec::new())?;
        let request = adapter.prepare_read(&root, "req-race", "lat_fs", Path::new("target.txt"))?;
        let permit = permit_for(&request, FsOperation::Read, &root);

        fs::remove_file(root.join("target.txt"))?;
        create_file_symlink(&outside, &root.join("target.txt"))?;

        let mut ledger = AuditLedger::in_memory()?;
        let error = adapter
            .execute(&permit, &mut ledger, 1_000_001)
            .expect_err("changed target must fail closed");

        assert!(matches!(
            error,
            FsError::LeafSymlink(_) | FsError::PathChangedAfterAuthorization { .. }
        ));
        Ok(())
    }

    #[test]
    fn raw_write_contents_do_not_appear_in_adapter_audit_events(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root = directory.path().join("workspace");
        fs::create_dir(&root)?;
        fs::write(root.join("notes.txt"), b"before")?;
        let adapter = FilesystemAdapter::new(vec![root.clone()], Vec::new())?;
        let request = adapter.prepare_write(
            &root,
            "req-secret",
            "lat_fs",
            Path::new("notes.txt"),
            b"do-not-log-this-value",
        )?;
        let permit = permit_for(&request, FsOperation::Write, &root);
        let mut ledger = AuditLedger::in_memory()?;

        adapter.execute(&permit, &mut ledger, 1_000_001)?;
        let audit = ledger
            .entries()?
            .into_iter()
            .map(|entry| entry.metadata_json)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!audit.contains("do-not-log-this-value"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_parent_escape_is_rejected() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::symlink;

        let directory = tempdir()?;
        let root = directory.path().join("workspace");
        let outside = directory.path().join("outside");
        fs::create_dir(&root)?;
        fs::create_dir(&outside)?;
        fs::write(outside.join("secret.txt"), b"outside")?;
        symlink(&outside, root.join("escape"))?;

        let adapter = FilesystemAdapter::new(vec![root.clone()], Vec::new())?;
        let error = adapter
            .prepare_read(
                &root,
                "req-escape",
                "lat_fs",
                Path::new("escape/secret.txt"),
            )
            .expect_err("symlinked parent must not escape root");

        assert!(matches!(error, FsError::PathOutsideRoot(_)));
        Ok(())
    }

    #[cfg(unix)]
    fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }
}

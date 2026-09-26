use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use latch_approvals::{ExecutionPermit, PermitSource};
use latch_audit::{AuditEntryInput, AuditError, AuditEventType, AuditLedger};
use latch_core::{ActionRequest, Resource};
use latch_secrets::{SecretBroker, SecretError, OPERATION as SECRET_OPERATION, RESOURCE_KIND as SECRET_RESOURCE_KIND};
use reqwest::{blocking::Client, Method, Url};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub const RESOURCE_KIND: &str = "github";
pub const READ_FILE: &str = "github.contents.read";
pub const WRITE_FILE: &str = "github.contents.write";
pub const DELETE_FILE: &str = "github.contents.delete";
pub const CREATE_BRANCH: &str = "github.branch.create";
pub const CREATE_PULL: &str = "github.pull.create";
pub const MERGE_PULL: &str = "github.pull.merge";
pub const GITHUB_SECRET_CONSUMER: &str = "github-api";
pub const MAX_CONTENT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubCall {
    ReadFile {
        repository: String,
        path: String,
        branch: String,
    },
    WriteFile {
        repository: String,
        path: String,
        branch: String,
        message: String,
        content: String,
        existing_sha: Option<String>,
    },
    DeleteFile {
        repository: String,
        path: String,
        branch: String,
        message: String,
        sha: String,
    },
    CreateBranch {
        repository: String,
        branch: String,
        from_sha: String,
    },
    CreatePullRequest {
        repository: String,
        title: String,
        body: String,
        head: String,
        base: String,
    },
    MergePullRequest {
        repository: String,
        number: u64,
        commit_title: String,
    },
}

impl GithubCall {
    fn operation(&self) -> &'static str {
        match self {
            Self::ReadFile { .. } => READ_FILE,
            Self::WriteFile { .. } => WRITE_FILE,
            Self::DeleteFile { .. } => DELETE_FILE,
            Self::CreateBranch { .. } => CREATE_BRANCH,
            Self::CreatePullRequest { .. } => CREATE_PULL,
            Self::MergePullRequest { .. } => MERGE_PULL,
        }
    }

    fn repository(&self) -> &str {
        match self {
            Self::ReadFile { repository, .. }
            | Self::WriteFile { repository, .. }
            | Self::DeleteFile { repository, .. }
            | Self::CreateBranch { repository, .. }
            | Self::CreatePullRequest { repository, .. }
            | Self::MergePullRequest { repository, .. } => repository,
        }
    }

    fn resource_value(&self) -> String {
        match self {
            Self::ReadFile {
                repository,
                path,
                branch,
            }
            | Self::WriteFile {
                repository,
                path,
                branch,
                ..
            }
            | Self::DeleteFile {
                repository,
                path,
                branch,
                ..
            } => format!("{repository}#{branch}:{path}"),
            Self::CreateBranch {
                repository, branch, ..
            } => format!("{repository}#branch:{branch}"),
            Self::CreatePullRequest {
                repository,
                head,
                base,
                ..
            } => format!("{repository}#pull:new:{head}->{base}"),
            Self::MergePullRequest {
                repository, number, ..
            } => format!("{repository}#pull:{number}"),
        }
    }

    fn audit_metadata(&self) -> Value {
        match self {
            Self::ReadFile {
                repository,
                path,
                branch,
            } => json!({
                "repository": repository,
                "path": path,
                "branch": branch,
                "risk": "READ",
            }),
            Self::WriteFile {
                repository,
                path,
                branch,
                content,
                existing_sha,
                ..
            } => json!({
                "repository": repository,
                "path": path,
                "branch": branch,
                "existing_sha": existing_sha,
                "content_sha256": sha256_bytes(content.as_bytes()),
                "content_bytes": content.len(),
                "risk": "MUTATING",
            }),
            Self::DeleteFile {
                repository,
                path,
                branch,
                sha,
                ..
            } => json!({
                "repository": repository,
                "path": path,
                "branch": branch,
                "sha": sha,
                "risk": "DESTRUCTIVE",
            }),
            Self::CreateBranch {
                repository,
                branch,
                from_sha,
            } => json!({
                "repository": repository,
                "branch": branch,
                "from_sha": from_sha,
                "risk": "MUTATING",
            }),
            Self::CreatePullRequest {
                repository,
                head,
                base,
                ..
            } => json!({
                "repository": repository,
                "head": head,
                "base": base,
                "risk": "MUTATING",
            }),
            Self::MergePullRequest {
                repository, number, ..
            } => json!({
                "repository": repository,
                "number": number,
                "risk": "DESTRUCTIVE",
            }),
        }
    }
}

pub trait GithubTransport {
    fn execute(&mut self, call: &GithubCall, token: &[u8]) -> std::result::Result<Value, String>;
}

pub struct GithubRestTransport {
    client: Client,
    base_url: Url,
}

impl fmt::Debug for GithubRestTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubRestTransport")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl GithubRestTransport {
    pub fn github_com(user_agent: &str) -> Result<Self> {
        Self::new("https://api.github.com/", user_agent)
    }

    pub fn new(base_url: &str, user_agent: &str) -> Result<Self> {
        if user_agent.trim().is_empty() {
            return Err(GithubError::InvalidRequest(
                "GitHub user agent must not be empty".into(),
            ));
        }
        let mut base_url = Url::parse(base_url)
            .map_err(|error| GithubError::InvalidRequest(format!("invalid GitHub base URL: {error}")))?;
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        let client = Client::builder()
            .user_agent(user_agent)
            .build()
            .map_err(|error| GithubError::Transport(error.to_string()))?;
        Ok(Self { client, base_url })
    }

    fn endpoint(&self, repository: &str, extra_segments: &[&str]) -> std::result::Result<Url, String> {
        let (owner, name) = split_repository(repository).map_err(|error| error.to_string())?;
        let mut url = self.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| "GitHub base URL cannot be used as a path base".to_string())?;
            segments.pop_if_empty();
            segments.push("repos");
            segments.push(owner);
            segments.push(name);
            for segment in extra_segments {
                segments.push(segment);
            }
        }
        Ok(url)
    }

    fn request_json(
        &self,
        method: Method,
        url: Url,
        token: &[u8],
        body: Option<Value>,
    ) -> std::result::Result<Value, String> {
        let token = std::str::from_utf8(token)
            .map_err(|_| "GitHub credential is not valid UTF-8".to_string())?;
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().map_err(|error| error.to_string())?;
        let status = response.status();
        let text = response.text().map_err(|error| error.to_string())?;
        if !status.is_success() {
            return Err(format!(
                "GitHub API returned {}: {}",
                status.as_u16(),
                truncate(&text, 4096)
            ));
        }
        if text.trim().is_empty() {
            return Ok(json!({"status": status.as_u16()}));
        }
        serde_json::from_str(&text)
            .map_err(|error| format!("GitHub API returned invalid JSON: {error}"))
    }
}

impl GithubTransport for GithubRestTransport {
    fn execute(&mut self, call: &GithubCall, token: &[u8]) -> std::result::Result<Value, String> {
        match call {
            GithubCall::ReadFile {
                repository,
                path,
                branch,
            } => {
                let path_segments = path.split('/').collect::<Vec<_>>();
                let mut extra = vec!["contents"];
                extra.extend(path_segments);
                let mut url = self.endpoint(repository, &extra)?;
                url.query_pairs_mut().append_pair("ref", branch);
                self.request_json(Method::GET, url, token, None)
            }
            GithubCall::WriteFile {
                repository,
                path,
                branch,
                message,
                content,
                existing_sha,
            } => {
                let path_segments = path.split('/').collect::<Vec<_>>();
                let mut extra = vec!["contents"];
                extra.extend(path_segments);
                let url = self.endpoint(repository, &extra)?;
                let mut body = json!({
                    "message": message,
                    "content": BASE64.encode(content.as_bytes()),
                    "branch": branch,
                });
                if let Some(sha) = existing_sha {
                    body["sha"] = Value::String(sha.clone());
                }
                self.request_json(Method::PUT, url, token, Some(body))
            }
            GithubCall::DeleteFile {
                repository,
                path,
                branch,
                message,
                sha,
            } => {
                let path_segments = path.split('/').collect::<Vec<_>>();
                let mut extra = vec!["contents"];
                extra.extend(path_segments);
                let url = self.endpoint(repository, &extra)?;
                self.request_json(
                    Method::DELETE,
                    url,
                    token,
                    Some(json!({"message": message, "sha": sha, "branch": branch})),
                )
            }
            GithubCall::CreateBranch {
                repository,
                branch,
                from_sha,
            } => {
                let url = self.endpoint(repository, &["git", "refs"])?;
                self.request_json(
                    Method::POST,
                    url,
                    token,
                    Some(json!({"ref": format!("refs/heads/{branch}"), "sha": from_sha})),
                )
            }
            GithubCall::CreatePullRequest {
                repository,
                title,
                body,
                head,
                base,
            } => {
                let url = self.endpoint(repository, &["pulls"])?;
                self.request_json(
                    Method::POST,
                    url,
                    token,
                    Some(json!({"title": title, "body": body, "head": head, "base": base})),
                )
            }
            GithubCall::MergePullRequest {
                repository,
                number,
                commit_title,
            } => {
                let number = number.to_string();
                let url = self.endpoint(repository, &["pulls", &number, "merge"])?;
                self.request_json(
                    Method::PUT,
                    url,
                    token,
                    Some(json!({"commit_title": commit_title, "merge_method": "squash"})),
                )
            }
        }
    }
}

pub struct GithubAdapter<T: GithubTransport> {
    transport: T,
}

impl<T: GithubTransport> GithubAdapter<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn prepare_read_file(
        &self,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        repository: &str,
        path: &str,
        branch: &str,
    ) -> Result<ActionRequest> {
        let call = GithubCall::ReadFile {
            repository: validated_repository(repository)?,
            path: validated_path(path)?,
            branch: validated_branch(branch)?,
        };
        Ok(request_from_call(request_id, session_id, call))
    }

    pub fn prepare_write_file(
        &self,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        repository: &str,
        path: &str,
        branch: &str,
        message: &str,
        content: &str,
        existing_sha: Option<&str>,
    ) -> Result<ActionRequest> {
        if content.len() > MAX_CONTENT_BYTES {
            return Err(GithubError::InvalidRequest(format!(
                "GitHub content exceeds {MAX_CONTENT_BYTES} bytes"
            )));
        }
        validate_message(message)?;
        let call = GithubCall::WriteFile {
            repository: validated_repository(repository)?,
            path: validated_path(path)?,
            branch: validated_branch(branch)?,
            message: message.into(),
            content: content.into(),
            existing_sha: existing_sha.map(validated_blob_sha).transpose()?,
        };
        Ok(request_from_call(request_id, session_id, call))
    }

    pub fn prepare_delete_file(
        &self,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        repository: &str,
        path: &str,
        branch: &str,
        message: &str,
        sha: &str,
    ) -> Result<ActionRequest> {
        validate_message(message)?;
        let call = GithubCall::DeleteFile {
            repository: validated_repository(repository)?,
            path: validated_path(path)?,
            branch: validated_branch(branch)?,
            message: message.into(),
            sha: validated_blob_sha(sha)?,
        };
        Ok(request_from_call(request_id, session_id, call))
    }

    pub fn prepare_create_branch(
        &self,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        repository: &str,
        branch: &str,
        from_sha: &str,
    ) -> Result<ActionRequest> {
        let call = GithubCall::CreateBranch {
            repository: validated_repository(repository)?,
            branch: validated_branch(branch)?,
            from_sha: validated_commit_sha(from_sha)?,
        };
        Ok(request_from_call(request_id, session_id, call))
    }

    pub fn prepare_create_pull_request(
        &self,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        repository: &str,
        title: &str,
        body: &str,
        head: &str,
        base: &str,
    ) -> Result<ActionRequest> {
        if title.trim().is_empty() || title.len() > 256 {
            return Err(GithubError::InvalidRequest(
                "pull request title must be 1-256 bytes".into(),
            ));
        }
        if body.len() > 65_536 {
            return Err(GithubError::InvalidRequest(
                "pull request body exceeds 65536 bytes".into(),
            ));
        }
        let call = GithubCall::CreatePullRequest {
            repository: validated_repository(repository)?,
            title: title.into(),
            body: body.into(),
            head: validated_branch(head)?,
            base: validated_branch(base)?,
        };
        Ok(request_from_call(request_id, session_id, call))
    }

    pub fn prepare_merge_pull_request(
        &self,
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        repository: &str,
        number: u64,
        commit_title: &str,
    ) -> Result<ActionRequest> {
        if number == 0 {
            return Err(GithubError::InvalidRequest(
                "pull request number must be greater than zero".into(),
            ));
        }
        validate_message(commit_title)?;
        let call = GithubCall::MergePullRequest {
            repository: validated_repository(repository)?,
            number,
            commit_title: commit_title.into(),
        };
        Ok(request_from_call(request_id, session_id, call))
    }

    pub fn execute(
        &mut self,
        action_permit: ExecutionPermit,
        secret_permit: ExecutionPermit,
        secrets: &SecretBroker,
        ledger: &mut AuditLedger,
        now_unix_ms: i64,
    ) -> Result<Value> {
        action_permit
            .validate_at(now_unix_ms)
            .map_err(|error| GithubError::InvalidPermit(error.to_string()))?;
        let action_request = action_permit.request();
        if action_request.resource.kind != RESOURCE_KIND {
            return Err(GithubError::InvalidPermit(
                "permit resource is not a GitHub resource".into(),
            ));
        }

        let call = call_from_request(action_request)?;
        if action_request.operation != call.operation()
            || action_request.resource.value != call.resource_value()
        {
            return Err(GithubError::InvalidPermit(
                "GitHub request no longer matches its authorized resource".into(),
            ));
        }
        enforce_authority(&call, action_permit.source())?;
        validate_secret_permit(
            &secret_permit,
            secrets,
            &action_request.session_id,
            now_unix_ms,
        )?;

        let (authority, grant_id) = permit_source(action_permit.source());
        ledger.append(AuditEntryInput {
            timestamp_unix_ms: now_unix_ms,
            event_type: AuditEventType::ToolForwarded,
            session_id: Some(action_request.session_id.clone()),
            request_id: Some(action_request.request_id.clone()),
            operation: Some(action_request.operation.clone()),
            resource_kind: Some(action_request.resource.kind.clone()),
            resource_value: Some(action_request.resource.value.clone()),
            decision: None,
            policy_rule: action_permit.rule_id().map(str::to_string),
            reason: Some("GitHub action passed adapter authority checks".into()),
            credential_ref: secret_permit
                .request()
                .arguments
                .get("credential_ref")
                .and_then(Value::as_str)
                .map(str::to_string),
            metadata: json!({
                "adapter": "github",
                "authority": authority,
                "grant_id": grant_id,
                "request_fingerprint": action_permit.request_fingerprint(),
                "call": call.audit_metadata(),
            }),
        })?;

        let transport_result = secrets.execute_with(
            secret_permit,
            ledger,
            now_unix_ms,
            |token| self.transport.execute(&call, token),
        )?;
        let result = transport_result.map_err(GithubError::Transport)?;
        let result_bytes = serde_json::to_vec(&result)
            .map_err(|error| GithubError::Transport(error.to_string()))?;

        ledger.append(AuditEntryInput {
            timestamp_unix_ms: now_unix_ms,
            event_type: AuditEventType::ToolResult,
            session_id: Some(action_request.session_id.clone()),
            request_id: Some(action_request.request_id.clone()),
            operation: Some(action_request.operation.clone()),
            resource_kind: Some(action_request.resource.kind.clone()),
            resource_value: Some(action_request.resource.value.clone()),
            decision: None,
            policy_rule: action_permit.rule_id().map(str::to_string),
            reason: Some("GitHub action completed".into()),
            credential_ref: None,
            metadata: json!({
                "adapter": "github",
                "result_bytes": result_bytes.len(),
                "result_sha256": sha256_bytes(&result_bytes),
            }),
        })?;

        Ok(result)
    }
}

fn request_from_call(
    request_id: impl Into<String>,
    session_id: impl Into<String>,
    call: GithubCall,
) -> ActionRequest {
    let operation = call.operation().to_string();
    let resource_value = call.resource_value();
    let arguments = match call {
        GithubCall::ReadFile {
            repository,
            path,
            branch,
        } => json!({"repository": repository, "path": path, "branch": branch}),
        GithubCall::WriteFile {
            repository,
            path,
            branch,
            message,
            content,
            existing_sha,
        } => json!({
            "repository": repository,
            "path": path,
            "branch": branch,
            "message": message,
            "content": content,
            "existing_sha": existing_sha,
        }),
        GithubCall::DeleteFile {
            repository,
            path,
            branch,
            message,
            sha,
        } => json!({
            "repository": repository,
            "path": path,
            "branch": branch,
            "message": message,
            "sha": sha,
        }),
        GithubCall::CreateBranch {
            repository,
            branch,
            from_sha,
        } => json!({"repository": repository, "branch": branch, "from_sha": from_sha}),
        GithubCall::CreatePullRequest {
            repository,
            title,
            body,
            head,
            base,
        } => json!({
            "repository": repository,
            "title": title,
            "body": body,
            "head": head,
            "base": base,
        }),
        GithubCall::MergePullRequest {
            repository,
            number,
            commit_title,
        } => json!({
            "repository": repository,
            "number": number,
            "commit_title": commit_title,
        }),
    };

    ActionRequest {
        request_id: request_id.into(),
        session_id: session_id.into(),
        operation,
        resource: Resource {
            kind: RESOURCE_KIND.into(),
            value: resource_value,
        },
        arguments,
    }
}

fn call_from_request(request: &ActionRequest) -> Result<GithubCall> {
    let repository = || {
        text_argument(&request.arguments, "repository")
            .and_then(validated_repository)
    };
    match request.operation.as_str() {
        READ_FILE => Ok(GithubCall::ReadFile {
            repository: repository()?,
            path: validated_path(text_argument(&request.arguments, "path")?)?,
            branch: validated_branch(text_argument(&request.arguments, "branch")?)?,
        }),
        WRITE_FILE => Ok(GithubCall::WriteFile {
            repository: repository()?,
            path: validated_path(text_argument(&request.arguments, "path")?)?,
            branch: validated_branch(text_argument(&request.arguments, "branch")?)?,
            message: validated_message_owned(text_argument(&request.arguments, "message")?)?,
            content: request
                .arguments
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| GithubError::InvalidPermit("missing content".into()))?
                .into(),
            existing_sha: request
                .arguments
                .get("existing_sha")
                .and_then(Value::as_str)
                .map(validated_blob_sha)
                .transpose()?,
        }),
        DELETE_FILE => Ok(GithubCall::DeleteFile {
            repository: repository()?,
            path: validated_path(text_argument(&request.arguments, "path")?)?,
            branch: validated_branch(text_argument(&request.arguments, "branch")?)?,
            message: validated_message_owned(text_argument(&request.arguments, "message")?)?,
            sha: validated_blob_sha(text_argument(&request.arguments, "sha")?)?,
        }),
        CREATE_BRANCH => Ok(GithubCall::CreateBranch {
            repository: repository()?,
            branch: validated_branch(text_argument(&request.arguments, "branch")?)?,
            from_sha: validated_commit_sha(text_argument(&request.arguments, "from_sha")?)?,
        }),
        CREATE_PULL => Ok(GithubCall::CreatePullRequest {
            repository: repository()?,
            title: text_argument(&request.arguments, "title")?.into(),
            body: text_argument(&request.arguments, "body")?.into(),
            head: validated_branch(text_argument(&request.arguments, "head")?)?,
            base: validated_branch(text_argument(&request.arguments, "base")?)?,
        }),
        MERGE_PULL => Ok(GithubCall::MergePullRequest {
            repository: repository()?,
            number: request
                .arguments
                .get("number")
                .and_then(Value::as_u64)
                .filter(|number| *number > 0)
                .ok_or_else(|| GithubError::InvalidPermit("missing pull request number".into()))?,
            commit_title: validated_message_owned(text_argument(
                &request.arguments,
                "commit_title",
            )?)?,
        }),
        other => Err(GithubError::InvalidPermit(format!(
            "unsupported GitHub operation {other}"
        ))),
    }
}

fn validate_secret_permit(
    permit: &ExecutionPermit,
    secrets: &SecretBroker,
    action_session_id: &str,
    now_unix_ms: i64,
) -> Result<()> {
    permit
        .validate_at(now_unix_ms)
        .map_err(|error| GithubError::InvalidPermit(error.to_string()))?;
    let request = permit.request();
    if request.session_id != action_session_id {
        return Err(GithubError::InvalidPermit(
            "GitHub action and secret permit belong to different sessions".into(),
        ));
    }
    if request.operation != SECRET_OPERATION || request.resource.kind != SECRET_RESOURCE_KIND {
        return Err(GithubError::InvalidPermit(
            "credential permit is not for secret.use".into(),
        ));
    }
    let credential_ref = text_argument(&request.arguments, "credential_ref")?;
    let consumer = text_argument(&request.arguments, "consumer")?;
    if consumer != GITHUB_SECRET_CONSUMER {
        return Err(GithubError::InvalidPermit(
            "credential is not scoped to the GitHub adapter".into(),
        ));
    }
    let version = request
        .arguments
        .get("secret_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| GithubError::InvalidPermit("missing secret_version".into()))?;
    let descriptor = secrets.descriptor(credential_ref)?;
    if descriptor.version != version
        || !descriptor
            .allowed_consumers
            .iter()
            .any(|candidate| candidate == GITHUB_SECRET_CONSUMER)
        || request.resource.value != format!("{credential_ref}#v{version}")
    {
        return Err(GithubError::InvalidPermit(
            "credential changed or is outside GitHub consumer scope".into(),
        ));
    }
    Ok(())
}

fn enforce_authority(call: &GithubCall, source: &PermitSource) -> Result<()> {
    match call {
        GithubCall::ReadFile { .. } => Ok(()),
        GithubCall::WriteFile { .. }
        | GithubCall::CreateBranch { .. }
        | GithubCall::CreatePullRequest { .. } => match source {
            PermitSource::Policy => Err(GithubError::HumanApprovalRequired),
            PermitSource::ApprovalOnce { .. } | PermitSource::ApprovalSession { .. } => Ok(()),
        },
        GithubCall::DeleteFile { .. } | GithubCall::MergePullRequest { .. } => match source {
            PermitSource::ApprovalOnce { .. } => Ok(()),
            PermitSource::Policy | PermitSource::ApprovalSession { .. } => {
                Err(GithubError::OneTimeApprovalRequired)
            }
        },
    }
}

fn validated_repository(repository: &str) -> Result<String> {
    split_repository(repository)?;
    Ok(repository.into())
}

fn split_repository(repository: &str) -> Result<(&str, &str)> {
    let mut parts = repository.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if owner.is_empty()
        || name.is_empty()
        || parts.next().is_some()
        || !owner.chars().all(valid_repo_character)
        || !name.chars().all(valid_repo_character)
    {
        return Err(GithubError::InvalidRequest(
            "repository must be an owner/name slug".into(),
        ));
    }
    Ok((owner, name))
}

fn valid_repo_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
}

fn validated_path(path: &str) -> Result<String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.len() > 1024
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(GithubError::InvalidRequest(
            "repository path must be a normalized relative path".into(),
        ));
    }
    Ok(path.into())
}

fn validated_branch(branch: &str) -> Result<String> {
    if branch.trim().is_empty()
        || branch.len() > 255
        || branch.starts_with('/')
        || branch.ends_with('/')
        || branch.ends_with('.')
        || branch.contains("..")
        || branch.contains("@{")
        || branch.chars().any(char::is_control)
    {
        return Err(GithubError::InvalidRequest("invalid Git branch name".into()));
    }
    Ok(branch.into())
}

fn validated_commit_sha(sha: &str) -> Result<String> {
    if sha.len() != 40 || !sha.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(GithubError::InvalidRequest(
            "commit SHA must be 40 hexadecimal characters".into(),
        ));
    }
    Ok(sha.to_ascii_lowercase())
}

fn validated_blob_sha(sha: &str) -> Result<String> {
    validated_commit_sha(sha)
}

fn validate_message(message: &str) -> Result<()> {
    if message.trim().is_empty() || message.len() > 4096 || message.chars().any(char::is_control) {
        return Err(GithubError::InvalidRequest(
            "GitHub commit message must be 1-4096 printable bytes".into(),
        ));
    }
    Ok(())
}

fn validated_message_owned(message: &str) -> Result<String> {
    validate_message(message)?;
    Ok(message.into())
}

fn text_argument<'a>(arguments: &'a Value, key: &str) -> Result<&'a str> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| GithubError::InvalidPermit(format!("missing or invalid {key}")))
}

fn permit_source(source: &PermitSource) -> (&'static str, Option<&str>) {
    match source {
        PermitSource::Policy => ("POLICY", None),
        PermitSource::ApprovalOnce { grant_id } => ("APPROVAL_ONCE", Some(grant_id)),
        PermitSource::ApprovalSession { grant_id } => ("APPROVAL_SESSION", Some(grant_id)),
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn truncate(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    #[error("invalid GitHub request: {0}")]
    InvalidRequest(String),
    #[error("invalid GitHub permit: {0}")]
    InvalidPermit(String),
    #[error("remote GitHub mutation requires human approval")]
    HumanApprovalRequired,
    #[error("destructive GitHub action requires a one-time human approval")]
    OneTimeApprovalRequired,
    #[error("GitHub transport error: {0}")]
    Transport(String),
    #[error("GitHub secret broker error: {0}")]
    Secret(#[from] SecretError),
    #[error("GitHub audit error: {0}")]
    Audit(#[from] AuditError),
}

pub type Result<T> = std::result::Result<T, GithubError>;

#[cfg(test)]
mod tests {
    use super::*;
    use latch_approvals::{ApprovalResolution, ApprovalStore};
    use latch_audit::AuditLedger;
    use latch_core::{evaluate, Effect, Policy, Rule, Session};
    use latch_secrets::SecretRegistration;

    #[derive(Default)]
    struct MockTransport {
        calls: Vec<GithubCall>,
    }

    impl GithubTransport for MockTransport {
        fn execute(
            &mut self,
            call: &GithubCall,
            token: &[u8],
        ) -> std::result::Result<Value, String> {
            assert_eq!(token, b"ghp_test_token");
            self.calls.push(call.clone());
            Ok(json!({"ok": true}))
        }
    }

    fn session() -> Session {
        Session {
            id: "lat_github".into(),
            principal: "local-user".into(),
            purpose: "test GitHub adapter".into(),
            expires_at_unix: 10_000,
            revoked: false,
        }
    }

    fn secrets() -> SecretBroker {
        SecretBroker::new([SecretRegistration::new(
            "github_main",
            b"ghp_test_token".to_vec(),
            [GITHUB_SECRET_CONSUMER],
        )
        .unwrap()])
        .unwrap()
    }

    fn permit(request: &ActionRequest, effect: Effect, ledger: &mut AuditLedger) -> ExecutionPermit {
        let policy = Policy {
            version: 1,
            rules: vec![Rule {
                id: "github-test".into(),
                effect,
                operation: request.operation.clone(),
                resource_kind: request.resource.kind.clone(),
                resource_prefix: request.resource.value.clone(),
            }],
        };
        let decision = evaluate(&session(), &policy, request, 1);
        let mut approvals = ApprovalStore::in_memory().unwrap();
        if effect == Effect::RequireApproval {
            let pending = approvals
                .submit(&session(), request, &decision, 1_000)
                .unwrap();
            approvals
                .resolve(
                    &pending.approval_id,
                    ApprovalResolution::AllowOnce,
                    "human",
                    1_001,
                    ledger,
                )
                .unwrap();
        }
        approvals
            .authorize(&session(), request, &decision, 1_002)
            .unwrap()
    }

    fn secret_permit(broker: &SecretBroker, ledger: &mut AuditLedger) -> ExecutionPermit {
        let request = broker
            .prepare_use(
                "req_secret",
                "lat_github",
                "github_main",
                GITHUB_SECRET_CONSUMER,
                "call GitHub API",
            )
            .unwrap();
        permit(&request, Effect::Allow, ledger)
    }

    #[test]
    fn read_can_be_policy_authorized() {
        let broker = secrets();
        let mut adapter = GithubAdapter::new(MockTransport::default());
        let request = adapter
            .prepare_read_file("req_read", "lat_github", "purysho/Latch", "README.md", "main")
            .unwrap();
        let mut ledger = AuditLedger::in_memory().unwrap();
        let action = permit(&request, Effect::Allow, &mut ledger);
        let credential = secret_permit(&broker, &mut ledger);
        let result = adapter
            .execute(action, credential, &broker, &mut ledger, 1_100)
            .unwrap();
        assert_eq!(result, json!({"ok": true}));
        assert_eq!(adapter.transport().calls.len(), 1);
        assert!(ledger.verify().unwrap().valid);
    }

    #[test]
    fn mutation_rejects_policy_only_authority() {
        let broker = secrets();
        let mut adapter = GithubAdapter::new(MockTransport::default());
        let request = adapter
            .prepare_write_file(
                "req_write",
                "lat_github",
                "purysho/Latch",
                "README.md",
                "main",
                "Update README",
                "new content",
                Some("0123456789abcdef0123456789abcdef01234567"),
            )
            .unwrap();
        let mut ledger = AuditLedger::in_memory().unwrap();
        let action = permit(&request, Effect::Allow, &mut ledger);
        let credential = secret_permit(&broker, &mut ledger);
        assert!(matches!(
            adapter.execute(action, credential, &broker, &mut ledger, 1_100),
            Err(GithubError::HumanApprovalRequired)
        ));
        assert!(adapter.transport().calls.is_empty());
    }

    #[test]
    fn mutation_executes_after_exact_human_approval() {
        let broker = secrets();
        let mut adapter = GithubAdapter::new(MockTransport::default());
        let request = adapter
            .prepare_create_branch(
                "req_branch",
                "lat_github",
                "purysho/Latch",
                "phase-9",
                "0123456789abcdef0123456789abcdef01234567",
            )
            .unwrap();
        let mut ledger = AuditLedger::in_memory().unwrap();
        let action = permit(&request, Effect::RequireApproval, &mut ledger);
        let credential = secret_permit(&broker, &mut ledger);
        adapter
            .execute(action, credential, &broker, &mut ledger, 1_100)
            .unwrap();
        assert_eq!(adapter.transport().calls.len(), 1);
    }

    #[test]
    fn path_traversal_is_rejected_before_policy() {
        let adapter = GithubAdapter::new(MockTransport::default());
        assert!(adapter
            .prepare_read_file(
                "req_bad",
                "lat_github",
                "purysho/Latch",
                "../secrets.txt",
                "main",
            )
            .is_err());
    }
}

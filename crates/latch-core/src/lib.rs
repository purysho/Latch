use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub principal: String,
    pub purpose: String,
    pub expires_at_unix: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRequest {
    pub request_id: String,
    pub session_id: String,
    pub operation: String,
    pub resource: Resource,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Effect {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub effect: Effect,
    pub operation: String,
    pub resource_kind: String,
    pub resource_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub version: u32,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub effect: Effect,
    pub rule_id: Option<String>,
    pub reason: String,
    pub request_fingerprint: String,
}

pub fn fingerprint(request: &ActionRequest) -> String {
    let canonical = serde_json::to_vec(request).expect("serializing ActionRequest cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    hex::encode(hasher.finalize())
}

fn operation_matches(pattern: &str, operation: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix(".*") {
        Some(prefix) => operation == prefix || operation.starts_with(&format!("{prefix}.")),
        None => pattern == operation,
    }
}

fn resource_matches(rule: &Rule, resource: &Resource) -> bool {
    rule.resource_kind == resource.kind && resource.value.starts_with(&rule.resource_prefix)
}

pub fn evaluate(session: &Session, policy: &Policy, request: &ActionRequest, now_unix: u64) -> Decision {
    let fp = fingerprint(request);

    if request.session_id != session.id {
        return Decision { effect: Effect::Deny, rule_id: None, reason: "request session does not match authenticated session".into(), request_fingerprint: fp };
    }
    if session.revoked {
        return Decision { effect: Effect::Deny, rule_id: None, reason: "session is revoked".into(), request_fingerprint: fp };
    }
    if now_unix >= session.expires_at_unix {
        return Decision { effect: Effect::Deny, rule_id: None, reason: "session is expired".into(), request_fingerprint: fp };
    }
    if request.operation.trim().is_empty() || request.resource.kind.trim().is_empty() || request.resource.value.trim().is_empty() {
        return Decision { effect: Effect::Deny, rule_id: None, reason: "request is malformed".into(), request_fingerprint: fp };
    }

    let matches: Vec<&Rule> = policy.rules.iter()
        .filter(|rule| operation_matches(&rule.operation, &request.operation) && resource_matches(rule, &request.resource))
        .collect();

    for effect in [Effect::Deny, Effect::RequireApproval, Effect::Allow] {
        if let Some(rule) = matches.iter().copied().find(|rule| rule.effect == effect) {
            let reason = match effect {
                Effect::Allow => "matched explicit allow rule",
                Effect::Deny => "matched explicit deny rule",
                Effect::RequireApproval => "matched rule requiring human approval",
            };
            return Decision { effect, rule_id: Some(rule.id.clone()), reason: reason.into(), request_fingerprint: fp };
        }
    }

    Decision { effect: Effect::Deny, rule_id: None, reason: "no policy rule granted authority".into(), request_fingerprint: fp }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn session() -> Session {
        Session { id: "lat_84f29".into(), principal: "local-user".into(), purpose: "fix-tests".into(), expires_at_unix: 2_000, revoked: false }
    }

    fn request(operation: &str, value: &str) -> ActionRequest {
        ActionRequest {
            request_id: "req_1".into(),
            session_id: "lat_84f29".into(),
            operation: operation.into(),
            resource: Resource { kind: "repository".into(), value: value.into() },
            arguments: json!({}),
        }
    }

    fn policy() -> Policy {
        Policy { version: 1, rules: vec![
            Rule { id: "deny-other".into(), effect: Effect::Deny, operation: "repository.delete".into(), resource_kind: "repository".into(), resource_prefix: "purysho/".into() },
            Rule { id: "approve-write".into(), effect: Effect::RequireApproval, operation: "repository.write".into(), resource_kind: "repository".into(), resource_prefix: "purysho/Witness".into() },
            Rule { id: "read-witness".into(), effect: Effect::Allow, operation: "repository.read".into(), resource_kind: "repository".into(), resource_prefix: "purysho/Witness".into() },
        ] }
    }

    #[test]
    fn defaults_to_deny() {
        assert_eq!(evaluate(&session(), &policy(), &request("repository.read", "purysho/Switchyard"), 1_000).effect, Effect::Deny);
    }

    #[test]
    fn explicit_allow_matches_scope() {
        assert_eq!(evaluate(&session(), &policy(), &request("repository.read", "purysho/Witness"), 1_000).effect, Effect::Allow);
    }

    #[test]
    fn approval_is_distinct_from_allow() {
        assert_eq!(evaluate(&session(), &policy(), &request("repository.write", "purysho/Witness"), 1_000).effect, Effect::RequireApproval);
    }

    #[test]
    fn deny_has_precedence() {
        let mut p = policy();
        p.rules.push(Rule { id: "broad-allow".into(), effect: Effect::Allow, operation: "repository.*".into(), resource_kind: "repository".into(), resource_prefix: "purysho/".into() });
        assert_eq!(evaluate(&session(), &p, &request("repository.delete", "purysho/Witness"), 1_000).effect, Effect::Deny);
    }

    #[test]
    fn expired_session_is_denied() {
        assert_eq!(evaluate(&session(), &policy(), &request("repository.read", "purysho/Witness"), 2_000).effect, Effect::Deny);
    }

    #[test]
    fn revoked_session_is_denied() {
        let mut s = session();
        s.revoked = true;
        assert_eq!(evaluate(&s, &policy(), &request("repository.read", "purysho/Witness"), 1_000).effect, Effect::Deny);
    }

    #[test]
    fn request_fingerprint_changes_when_material_field_changes() {
        let a = request("repository.write", "purysho/Witness");
        let mut b = a.clone();
        b.resource.value = "purysho/Switchyard".into();
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }
}

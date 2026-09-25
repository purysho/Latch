# Policy model

Latch V1 uses a small declarative policy model compiled into typed core rules.

Example:

```yaml
version: 1
agent:
  purpose: fix-tests

rules:
  - id: witness-read
    effect: allow
    operation: filesystem.read
    resource:
      kind: filesystem
      root: C:\\Projects\\Witness

  - id: witness-write
    effect: allow
    operation: filesystem.write
    resource:
      kind: filesystem
      root: C:\\Projects\\Witness

  - id: git-push-review
    effect: approval
    operation: shell.git.push
    resource:
      kind: workspace
      id: witness

  - id: protected-security-files
    effect: deny
    operation: filesystem.*
    resource:
      kind: filesystem
      root: C:\\Users\\*\\.ssh
```

## Evaluation semantics

1. Invalid or expired session → DENY.
2. Malformed / unknown operation or resource → DENY.
3. Explicit matching DENY has highest precedence.
4. Matching REQUIRE_APPROVAL is next.
5. Matching ALLOW is next.
6. No match → DENY.

A match must include operation and resource scope. Argument constraints are evaluated when declared.

The evaluator never uses free-form model text to infer additional permission.


## Approval semantics

A policy result of `REQUIRE_APPROVAL` never authorizes execution by itself.

### Allow once

An allow-once grant is bound to:

- session ID;
- matched approval policy rule;
- complete canonical request fingerprint, including request ID, operation, resource and arguments;
- expiry no later than the session.

The grant is atomically consumed before an execution permit is returned. Reusing the same request cannot consume the same grant twice.

### Allow for this session

A session grant is intentionally narrower than a broad resource permission. It binds to:

- the same session;
- the same matched approval rule;
- the same operation;
- the exact resource;
- the exact arguments.

Only the request ID is excluded from the session-scope fingerprint, allowing repeated instances of the same capability shape. Changing a branch name, path, command arguments, tool arguments, resource, or operation requires new approval.

Session grants may have an earlier fixed expiry but can never outlive the underlying session.

### Deny and policy changes

A human denial resolves that exact approval request without creating authority.

Every new execution attempt is still evaluated against current policy. A later explicit policy DENY wins even when an older approval grant exists.

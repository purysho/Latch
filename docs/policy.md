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

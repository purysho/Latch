# Threat model

## Security objective

Latch assumes an AI agent will eventually request or attempt an action it should not be allowed to perform. The product exists to keep that request from becoming authority.

## Trusted computing base

V1 minimizes the trusted computing base to:

- policy parser and deterministic evaluator
- session / identity store
- approval binding and grant store
- authorization proxy
- secret broker
- audit ledger
- approval UI insofar as it represents scope faithfully

Adapters, models, repository content, web content, tool descriptions, tool results, emails, package metadata, and generated code are not trusted policy inputs.

## Trust boundaries

### B1 — Agent → Latch

Agent requests are untrusted structured input. Claimed model/client identity is metadata only and grants no authority.

### B2 — External content → Agent / Latch

Repository files, READMEs, comments, issue text, web pages and MCP results are data. They cannot mutate active policy or grants.

### B3 — Latch → Adapter

Only a normalized request carrying an ALLOW decision or a matching live approval grant may cross this boundary.

### B4 — Latch → Secret source

Credentials are resolved only after authorization. Raw secret values must not enter agent-visible results or audit events.

### B5 — Human → Approval store

Approvals must bind to an exact canonical request fingerprint and explicit lifetime/scope.

## Primary threats

1. Prompt injection inducing credential or filesystem access.
2. Scope escalation from a permitted resource to a sibling or broader resource.
3. Path traversal and symlink/junction escape.
4. Shell metacharacters, chaining and secondary interpreter escape.
5. Tool-name spoofing or MCP schema drift.
6. Approval replay after any material request field changes.
7. Stale or expired sessions / grants.
8. Secret leakage into logs, errors, results or telemetry.
9. Policy mutation driven by untrusted content.
10. Audit history alteration.
11. Ambiguous UI causing a user to approve broader scope than requested.
12. Race conditions between authorization, approval and execution.

## Required negative tests

Every threat above must gain a regression test before the corresponding adapter is considered production-capable.

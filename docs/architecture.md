# Architecture

## Design rule

**No operation executes before an authorization decision exists.**

The system is split so the evaluator can be tested without a shell, network connection, credential, MCP server, or desktop UI.

## Core flow

1. A live session submits an `ActionRequest`.
2. Latch canonicalizes the resource and arguments.
3. The evaluator checks session validity and ordered policy rules.
4. The result is one of:
   - `ALLOW`
   - `DENY`
   - `REQUIRE_APPROVAL`
5. A decision includes a stable explanation and matched rule ID.
6. For approval-required requests, the canonical request is fingerprinted.
7. Only an exact, live approval grant can satisfy that request.
8. Only then may an adapter receive execution authority.
9. Decision and execution events are written to the audit ledger.

## Crate boundaries

### latch-core

Pure authorization logic:
- identities and sessions
- typed resources
- operations
- policies
- requests
- canonical fingerprints
- deterministic evaluator
- decisions and explanations

It performs no external side effects.

### future latch-audit

SQLite persistence and hash-chained audit events.

### future latch-adapters

Filesystem, controlled shell, MCP and GitHub adapters. Each adapter must require an already-authorized execution token rather than evaluating policy itself.

### desktop

Tauri + React local control plane. The UI is not policy. It displays state, requests approval, and calls trusted backend commands.

## Security invariants

A. No operation executes before an authorization decision exists.

B. DENY can never result in adapter execution.

C. Approval is bound to the exact request fingerprint.

D. Expired sessions and grants provide no authority.

E. A narrower resource grant cannot authorize a broader resource.

F. Secrets never appear in audit logs.

G. Agent-supplied text cannot modify active policy.

H. Tool identity is not derived solely from a display name.

I. Filesystem authorization uses canonical resolved paths.

J. Audit history alteration is detectable.

## Concurrency rule

Authorization and execution must carry an immutable request ID and canonical fingerprint. A later mutation is a new request and requires a new decision.

## UI rule

Approval presentation is security-critical. Operation, target, risk, scope, duration and requesting agent must be visible without expansion. “Allow once” is the visually primary positive action; broader grants are secondary and explicit.

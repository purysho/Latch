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
7. Request receipt and the resulting authorization decision are appended atomically to the SQLite audit ledger.
8. The audit ledger chains every entry to the previous SHA-256 hash and can verify historical integrity.
9. Only an exact, live approval grant can satisfy an approval-required request.
10. Only then may an adapter receive execution authority.
11. Execution results will be appended to the same ledger once adapters are introduced.

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

### latch-audit

Local audit persistence:
- immutable SQLite event rows
- request IDs and authorization-decision records
- atomic request + decision recording
- SHA-256 hash chaining
- chain verification
- argument digests rather than raw request arguments
- update/delete prevention at the SQLite schema boundary

It does not execute tools or decide policy.

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

Audit appends use an immediate SQLite transaction so chain position and insertion occur under one writer lock.

## Audit integrity boundary

The V1 hash chain detects mutation, insertion, deletion from the middle, reordering, and broken linkage when the stored chain is verified. Like an unsigned local hash chain generally, it cannot independently prove that an attacker with unrestricted database replacement access did not replace the entire database or truncate and replace the trusted chain head. A future signed/exported checkpoint can anchor the head outside the database if that threat enters scope.

## UI rule

Approval presentation is security-critical. Operation, target, risk, scope, duration and requesting agent must be visible without expansion. “Allow once” is the visually primary positive action; broader grants are secondary and explicit.

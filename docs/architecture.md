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
11. Execution adapters append forwarding and result events to the same ledger. Filesystem and controlled-process execution both use this boundary.

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
- opaque authorization decisions whose fields cannot be fabricated externally

It performs no external side effects.

### latch-approvals

Human approval and execution authority:

- persists pending approval requests and grants in SQLite;
- accepts only genuine opaque `latch-core::Decision` values;
- mints non-cloneable execution permits for direct policy ALLOW decisions or validated approval grants;
- binds allow-once grants to the complete request fingerprint;
- binds allow-for-session grants to session + policy rule + operation + exact resource + exact arguments, allowing only a fresh request ID;
- consumes allow-once grants atomically under an immediate SQLite transaction;
- caps every grant and permit at the underlying session expiry;
- records approval grants and denials in the audit ledger before approval-store commit;
- never lets an existing approval override a later policy DENY.

Adapters consume execution permits by value and recheck permit expiry immediately before side effects.

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

### latch-fs

The first execution adapter:

- canonical configured roots;
- relative-path normalization with parent traversal rejected;
- distinct read, write, create and delete operations;
- leaf-symlink rejection;
- symlinked-parent escape detection through canonicalization;
- protected-path enforcement, including protected targets that do not yet exist;
- revalidation immediately before I/O;
- exact request/content binding through `ExecutionPermit`;
- `TOOL_FORWARDED` and `TOOL_RESULT` audit events around actual I/O.

The adapter never evaluates policy. It accepts only a non-cloneable execution permit minted by `latch-approvals` from a genuine policy ALLOW decision or a matching live approval grant.

### latch-shell

Controlled process execution:

- trusted command IDs map to canonical executable paths;
- executable SHA-256 is bound into the command rule;
- command-rule fingerprints bind executable identity, argument policy, working roots, timeout, output cap and environment policy;
- input command lines are parsed structurally;
- compound expressions and shell operators are rejected;
- V1 refuses registration of command shells such as cmd, PowerShell, sh, bash, zsh, fish and WSL;
- working directories are canonicalized and restricted to command-specific roots;
- environment inheritance is empty unless explicitly allowlisted;
- stdin is closed by the process runner;
- timeouts tear down the contained process tree;
- stdout/stderr are captured with a configured memory ceiling;
- audit records hashes and sizes of process output rather than copying captured output into the ledger.

The adapter does not claim to sandbox an allowed developer command. A permitted pytest, npm, cargo, git or language-runtime command can still perform whatever that executable and project configuration allow.

### future adapters

MCP and GitHub adapters follow the same rule: normalize first, authorize centrally, then execute only from an immutable permit.

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

Authorization and execution carry an immutable request ID and canonical fingerprint. A later mutation is a new request and requires a new decision.

Allow-once grants are claimed under an immediate SQLite writer transaction and marked consumed before a permit is returned. Concurrent consumers cannot receive two permits from one grant.

Execution permits are deliberately non-cloneable and adapters consume them by value. This prevents in-process reuse after grant consumption.

Audit appends use an immediate SQLite transaction so chain position and insertion occur under one writer lock. Approval resolution writes its audit event before committing the approval-store transaction; this fails closed if audit persistence is unavailable, though the two SQLite databases are not a distributed atomic transaction.

## Audit integrity boundary

The V1 hash chain detects mutation, insertion, deletion from the middle, reordering, and broken linkage when the stored chain is verified. Like an unsigned local hash chain generally, it cannot independently prove that an attacker with unrestricted database replacement access did not replace the entire database or truncate and replace the trusted chain head. A future signed/exported checkpoint can anchor the head outside the database if that threat enters scope.

## UI rule

Approval presentation is security-critical. Operation, target, risk, scope, duration and requesting agent must be visible without expansion. “Allow once” is the visually primary positive action; broader grants are secondary and explicit.

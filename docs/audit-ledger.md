# Audit ledger

Latch Phase 2 provides a local SQLite audit ledger in `crates/latch-audit`.

## Goals

The ledger records material security decisions in a form that is:

- local-first;
- append-only through the supported API;
- resistant to accidental mutation;
- hash chained so historical alteration is detectable;
- queryable without storing reusable credentials or raw request arguments.

## Stored authorization pair

A call to `record_authorization` writes two events in one immediate SQLite transaction:

1. `REQUEST_RECEIVED`
2. one of `POLICY_ALLOW`, `POLICY_DENY`, or `APPROVAL_REQUIRED`

Both records carry the session ID, request ID, operation and target resource. The decision record also carries the matched rule and explanation.

The request's canonical fingerprint is stored. Request arguments are represented by a SHA-256 digest rather than copied verbatim into the ledger. This is intentionally conservative until adapter-specific redaction exists.

## Hash chain

Each row contains:

- a monotonically increasing sequence number;
- `previous_hash`;
- `entry_hash`.

The first entry points to a fixed genesis hash. Every later entry points to the verified hash of the previous row.

The entry hash covers the full stored event content, its sequence, and its previous hash using an unambiguous length-prefixed encoding.

`AuditLedger::verify` checks:

- sequence continuity;
- previous-hash linkage;
- recomputed entry hashes.

## SQLite immutability

The schema installs triggers that reject `UPDATE` and `DELETE` against `audit_entries`. Tests deliberately remove the update trigger, mutate historical content, and prove chain verification then fails.

## Security boundary and limitation

A local SHA-256 chain is tamper-evident, not magically tamper-proof. It detects historical mutation relative to the chain being verified. An attacker able to replace the complete database and every trusted copy of its head can construct a different valid chain.

Latch can later anchor periodic chain heads in signed/exported checkpoints if protection against full-database replacement or tail truncation becomes a V1 requirement.

## Event vocabulary

The Phase 2 schema reserves the material event types from the project brief:

`SESSION_CREATED`, `SESSION_EXPIRED`, `REQUEST_RECEIVED`, `POLICY_ALLOW`,
`POLICY_DENY`, `APPROVAL_REQUIRED`, `APPROVAL_GRANTED`, `APPROVAL_DENIED`,
`SECRET_USED`, `TOOL_CHANGED`, `TOOL_FORWARDED`, `TOOL_RESULT`, and
`POLICY_CHANGED`.

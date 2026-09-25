# Approval system

Phase 5 introduces `crates/latch-approvals`.

## Lifecycle

```text
REQUIRE_APPROVAL
       |
       v
pending approval
   |       |       |
   v       v       v
 DENY   ALLOW    ALLOW FOR
        ONCE      SESSION
          \       /
           v     v
        live grant
            |
 current policy re-check
            |
     exact grant match
            |
   ExecutionPermit
            |
       adapter consumes
```

## Pending requests

A pending record stores identifiers and authorization-relevant metadata, not raw request arguments:

- approval ID;
- request ID;
- session ID;
- request fingerprint;
- session-scope fingerprint;
- operation;
- resource kind and value;
- matched policy rule;
- creation/expiry timestamps;
- status and human resolution metadata.

Pending requests expire with their session.

## Exact request fingerprint

`ALLOW ONCE` uses `latch-core::fingerprint(ActionRequest)`. Any material request change changes the fingerprint.

The one-shot grant is claimed using an immediate SQLite transaction and marked consumed before Latch returns authority.

## Session grant

`ALLOW FOR THIS SESSION` does not mean “anything matching this resource prefix.”

Latch derives a second fingerprint from the full canonical request after clearing only `request_id`. Therefore a fresh request ID can repeat the exact capability, but changes to operation, resource, session or arguments require new approval.

The grant can specify an earlier expiry and can never outlive the session.

## Current policy still wins

Approval grants do not replace policy evaluation. Each execution attempt receives a current `Decision`.

- current `DENY` → denied;
- current `ALLOW` → policy permit;
- current `REQUIRE_APPROVAL` → a matching live grant is required.

This means administrators can revoke previously approved capability by changing policy to DENY.

## Execution permit

The permit type is owned by `latch-approvals`, not the adapters.

It is intentionally not `Clone`. Filesystem and controlled-process adapters accept it by value and validate its expiration timestamp immediately before execution.

This provides a second replay boundary after one-shot database consumption.

## Audit

Human resolution writes `APPROVAL_GRANTED` or `APPROVAL_DENIED` to the tamper-evident audit ledger, including:

- approval ID;
- grant ID when created;
- grant mode;
- expiry;
- request or scope fingerprint;
- resolver principal via the event reason.

Raw request arguments are not copied into approval audit metadata.

The audit ledger and approval store are separate SQLite databases. Resolution appends audit first and commits the approval-store transaction second. If audit append fails, authority is not committed. A later approval-store commit failure can leave an orphan audit event; this is preferable to creating unaudited authority and is explicitly not presented as a distributed atomic transaction.

## Regression coverage

Phase 5 tests prove:

- direct ALLOW still mints policy authority;
- allow-once works once and only once;
- changing a material field invalidates prior approval;
- session grants allow only the same capability shape;
- grants do not cross sessions;
- expired grants provide no authority;
- human denial creates no grant;
- a later policy DENY overrides a live grant;
- grant and permit expiry are capped by session expiry;
- approval audit metadata excludes request arguments;
- pending/grant persistence survives reopen;
- two concurrent consumers can obtain only one permit from one allow-once grant.

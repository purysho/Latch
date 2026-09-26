# Secret broker

Phase 8 adds a credential boundary to Latch.

## Invariants

- Agents and policy requests carry a credential reference, never credential bytes.
- A secret is scoped to an explicit consumer.
- Authorization binds to a monotonically increasing secret version.
- Rotating a secret invalidates permits created for the previous version.
- The audit ledger records the credential reference, consumer, authority source and request fingerprint, but not the credential material.
- Secret material is zeroed when a record is replaced or dropped.
- The broker exposes material only inside the authorized consumer callback.

The broker deliberately does not implement a general `get_secret()` API.

## Flow

```text
agent intent
  -> secret.use request (reference + consumer + version)
  -> policy / approval
  -> ExecutionPermit
  -> version + consumer revalidation
  -> SECRET_USED audit event
  -> material exposed only inside the consumer boundary
```

Secret storage at rest remains a host responsibility in v0.1. The broker accepts material from the trusted local control plane; it does not write plaintext credentials to disk.

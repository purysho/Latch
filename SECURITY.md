# Security policy

Latch is security infrastructure under active development.

## Reporting

Please do not publish a suspected security vulnerability as a public issue. Report it privately to the repository owner through GitHub's private vulnerability reporting facilities when available.

## Current guarantees

Only behavior covered by the current release and regression tests should be treated as implemented. Design documents describe intended invariants; unfinished adapters are not security claims.

## Core invariants

- deny by default
- no execution before authorization
- DENY never reaches an adapter
- approvals bind to exact request fingerprints
- expired authority stops working
- narrower scope cannot authorize broader scope
- secrets must not enter audit logs
- untrusted content cannot mutate policy
- tool identity is stronger than display name
- filesystem authorization will use canonical resolved paths
- audit history will be tamper-evident

Every reproduced security flaw should gain a regression test.

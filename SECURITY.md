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


## Filesystem adapter

Phase 3 treats paths as hostile input. Filesystem requests are root-relative, canonicalized before authorization, revalidated before execution, and rejected on parent traversal, root escape, protected paths, or leaf symlinks. The adapter executes only from an immutable permit minted from an exact ALLOW decision.


## Controlled process adapter

Phase 4 does not expose arbitrary shell execution. Configured command IDs map to canonical executables, compound shell expressions are rejected before authorization, common command shells are not registrable in V1, and execution requires an immutable ALLOW permit.

Working directories remain inside canonical command-specific roots. Executable content is hashed at rule registration and rechecked before spawn. Environment inheritance is explicit rather than ambient. Process execution has a mandatory timeout and bounded output capture.

Allowing a developer command is still substantial authority. Latch does not claim that an allowed test runner, package manager, compiler, VCS client or language runtime is internally safe; command policy must remain least-privilege.

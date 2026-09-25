# Filesystem adapter

Phase 3 introduces `crates/latch-fs`, the first adapter that can perform external side effects.

## Security model

The filesystem adapter does not decide policy.

The flow is deliberately split:

1. Latch receives a root-relative filesystem intent.
2. `latch-fs` normalizes it into an exact canonical `ActionRequest`.
3. `latch-core` evaluates policy.
4. Only an exact `ALLOW` decision can mint an `ExecutionPermit`.
5. `latch-fs` executes the operation encoded in that permit.
6. The adapter writes `TOOL_FORWARDED` before actual I/O and `TOOL_RESULT` after it.

A caller cannot authorize one path or byte sequence and then provide a different one to the adapter. The permit carries the complete authorized request.

## Operations

V1 Phase 3 distinguishes:

- `filesystem.read`
- `filesystem.write`
- `filesystem.create`
- `filesystem.delete`

Create and delete are not aliases for write. Policies can grant them independently.

Write/create content is included in the request fingerprint. The adapter stores content as base64 inside the in-memory request plus a SHA-256 content digest. Audit events never copy the raw content.

## Root containment

Every adapter instance receives one or more configured filesystem roots.

Configured roots are canonicalized when the adapter starts. User-facing paths are root-relative and must not contain:

- absolute prefixes;
- root components;
- `..` parent traversal.

For existing targets the full path is canonicalized before policy evaluation and again immediately before execution. The canonical target must remain inside one configured root.

For create operations, the existing parent is canonicalized and the new filename is appended only after that parent passes root and protected-path checks.

Rust's component-aware `Path::starts_with` is used for containment rather than string-prefix matching.

## Symlinks and reparse points

Leaf symlinks are rejected rather than followed.

Symlinked parent directories are canonicalized. If they resolve outside an allowed root, preparation or execution fails closed.

The same canonical-path strategy applies to Windows reparse-point/junction resolution through `std::fs::canonicalize`; the workspace tests now run on both Ubuntu and Windows.

There remains an operating-system race window between final path validation and the filesystem syscall because Phase 3 uses portable standard-library file APIs. Latch revalidates immediately before I/O and uses `create_new` for creation, but handle-relative/open-no-follow primitives are a future hardening layer if the threat model expands to a concurrently malicious local process with write access to authorized directories.

## Protected paths

Protected paths are a defense-in-depth boundary independent of policy.

They may point to existing files/directories or targets that do not yet exist. A protected directory protects its descendants.

The adapter rechecks protected paths at execution even if a caller somehow presents a valid `ALLOW` permit for that target.

## Audit behavior

Actual I/O is never attempted until the pre-execution `TOOL_FORWARDED` event is successfully appended.

After the filesystem operation, `TOOL_RESULT` records only:

- adapter name;
- success/error outcome;
- byte count when relevant;
- a stable error code on failure.

Raw read/write contents are not copied into adapter audit metadata.

## Negative tests

Phase 3 regression coverage includes:

- parent traversal;
- symlinked-parent escape;
- leaf-symlink replacement after authorization;
- protected existing paths;
- protected create targets that do not yet exist;
- exact operation separation;
- request-bound write content;
- audit-chain integration;
- raw-content non-persistence.

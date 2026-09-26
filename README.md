# Latch

**Authority for agents.**

Latch is a local-first security broker for AI agents. It sits between an agent and the tools, files, shells, MCP servers, secrets, APIs, and repositories that agent wants to use, then deterministically decides whether each requested action is **allowed**, **denied**, or **requires human approval**.

> Capability does not imply authority.

## Status

**Latch v0.1.0 is a public preview.**

The enforcement layer is implemented as tested Rust crates: deterministic authorization, a tamper-evident audit ledger, scoped filesystem and shell execution, persistent approvals, an MCP proxy, a secret broker, and a GitHub adapter. The desktop application is a hardened local **preview/control-plane surface** and is intentionally labelled as such; v0.1 does not claim that every adapter is live-wired into the UI.

- [Latest release](https://github.com/purysho/Latch/releases/latest)
- [Release notes](RELEASE_NOTES_v0.1.0.md)
- [Security model](SECURITY.md)
- [Adversarial test matrix](docs/adversarial-testing.md)

The Windows preview build is not code-signed yet, so Windows may show a reputation warning.

## Principles

- deny by default
- agent/model output is untrusted intent
- policy is separate from identity
- grants are least-privilege and time-bound
- approvals bind to the exact request
- repository/web/tool content is data, never policy
- secrets stay outside the agent whenever possible
- every material decision is explainable and auditable
- v0.1 is fully local: no account, cloud control plane, telemetry, or mandatory service

## Architecture

~~~text
Agent request
    |
    v
Session identity
    |
    v
Request normalization
    |
    v
Deterministic policy evaluator
    |------------|-------------------|
    v            v                   v
  ALLOW        DENY         REQUIRE_APPROVAL
    |                                |
    |                         exact fingerprint
    |                                |
    +-------------+------------------+
                  v
          execution boundary
    |-------------|-------------|-------------|-------------|
    v             v             v             v             v
 filesystem     shell          MCP         secrets        GitHub
    |             |             |             |             |
    +-------------+-------------+-------------+-------------+
                                  |
                                  v
                         SQLite audit ledger
                                  |
                                  v
                           SHA-256 hash chain
~~~

No adapter may execute before an authorization decision exists.

## V0.1 workspace

~~~text
crates/
  latch-core/         typed request, policy, resource and decision model
  latch-audit/        immutable SQLite event ledger + hash-chain verification
  latch-approvals/    pending approvals, grants, expiry and single-use permits
  latch-fs/           canonical, permit-gated filesystem adapter
  latch-shell/        structured, allowlisted controlled-process execution
  latch-mcp/          MCP discovery, schema validation, stdio transport and proxy
  latch-secrets/      version-bound secret broker with scoped consumers
  latch-github/       GitHub REST adapter with approval and secret boundaries
  latch-adversarial/  cross-boundary adversarial regression tests
apps/
  desktop/            Tauri + React local control-plane preview
docs/
  threat-model.md
  architecture.md
  audit-ledger.md
  policy.md
  approval-system.md
  controlled-shell.md
  filesystem-adapter.md
  secret-broker.md
  github-adapter.md
  ui-hardening.md
  adversarial-testing.md
  adr/
~~~

## Completed phases

1. Architecture + threat model — complete
2. Authorization core — complete
3. Audit ledger — complete
4. Filesystem adapter — complete
5. Controlled shell — complete
6. Approval system — complete
7. MCP proxy — complete
8. Secret broker — complete
9. GitHub adapter — complete
10. Local UI hardening — complete for v0.1 preview
11. Adversarial testing — complete for v0.1 release gate

### Phase 7 — MCP proxy

Latch can discover MCP tools over stdio, validate descriptors and JSON schemas, bind policy to provider/tool identity, refresh discovery immediately before forwarding, and fail closed if a tool changes after authorization.

### Phase 8 — secret broker

Agents receive a credential **reference**, never credential bytes. Secret use is scoped to an intended consumer and version. Rotation invalidates stale permits, and audit events record the reference and consumer without recording the secret material.

### Phase 9 — GitHub adapter

GitHub reads may be explicitly policy-authorized. Remote mutations require human approval. Destructive delete/merge actions require **one-time** human approval rather than a reusable session grant. The adapter obtains credentials through the secret broker instead of owning a token.

### Phase 10 — UI hardening

The desktop preview distinguishes demonstration data from live enforcement, removes private-project references, uses a restrictive CSP, exposes a narrow read-only runtime status command, supports keyboard focus/reduced motion, and does not load remote scripts or images.

### Phase 11 — adversarial testing

The release gate exercises prompt/instruction injection, approval mutation, secret rotation, reusable-grant escalation, MCP provider impersonation/schema drift, filesystem traversal, shell escape, invalid MCP output, and audit-ledger tampering assumptions.

## Verification

Every push to main must pass:

~~~bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
~~~

The Rust test suite also runs on Windows. The React/TypeScript production build and Tauri host compile are separate CI jobs.

A green gate is evidence that the documented invariants have executable regression coverage; it is not a claim that the software is vulnerability-free.

## Development

~~~bash
cargo test --workspace

cd apps/desktop
npm install
npm run build
npm run tauri dev
~~~

## V0.1 boundary

Latch v0.1 is an engineering preview for evaluating local agent-authority boundaries. It is **not yet a drop-in universal agent gateway** and should not be treated as the sole control protecting production credentials or irreversible infrastructure. The next milestone is to wire the hardened desktop control plane to the enforcement crates end-to-end and broaden integration testing with real MCP clients and providers.

## License

MIT. Copyright © Purysho.

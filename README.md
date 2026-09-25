# Latch

**Authority for agents.**

Latch is a local-first security broker for AI agents. It sits between an agent and the tools, files, shells, APIs, and repositories that agent wants to use, then deterministically decides whether each requested action is **allowed**, **denied**, or **requires human approval**.

> Capability does not imply authority.

## Status

Latch is in active development. Phases 0–4 establish the security architecture, deterministic authorization core, tamper-evident audit ledger, scoped filesystem I/O, and a permit-gated controlled process runner that never invokes an implicit OS shell.

## Principles

- deny by default
- agent/model output is untrusted intent
- policy is separate from identity
- grants are least-privilege and time-bound
- approvals bind to the exact request
- repository/web/tool content is data, never policy
- secrets stay outside the agent whenever possible
- every material decision is explainable and auditable
- V1 is fully local: no account, cloud control plane, telemetry, or mandatory service

## Architecture

```text
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
          adapter execution
                  |
                  v
      SQLite audit ledger
                  |
                  v
       SHA-256 hash chain
```

No adapter may execute before an authorization decision exists.

## Workspace

```text
crates/
  latch-core/       typed request, policy, resource and decision model
  latch-audit/      immutable SQLite event ledger + hash-chain verification
  latch-fs/         canonical, permit-gated filesystem adapter
  latch-shell/      structured, allowlisted controlled process execution
apps/
  desktop/          Tauri + React local control-plane UI
docs/
  threat-model.md
  architecture.md
  audit-ledger.md
  policy.md
  adr/
```

## Development

The Rust authorization and audit crates are independent of the UI and future execution adapters.

```bash
cargo test --workspace
```

The desktop app follows the visual language of the Purysho desktop tools while using a restrained glass system designed around authorization state, scope, and human review.

## Roadmap

1. Architecture + threat model — complete
2. Authorization core — complete
3. Audit ledger — complete
4. Filesystem adapter — complete
5. Controlled shell — complete
6. Approval system
7. MCP proxy
8. Secret broker
9. GitHub adapter
10. Local UI hardening
11. Adversarial testing

External action execution is deliberately gated until the authorization foundation is proven.

## License

MIT. Copyright © Purysho.

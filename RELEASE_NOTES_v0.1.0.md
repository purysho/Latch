# Latch v0.1.0

**Authority for agents.**

Latch v0.1.0 is the first public preview of the local-first authorization layer for AI agents.

## What is included

- deterministic, deny-by-default authorization;
- typed sessions, resources, operations and request fingerprints;
- persistent exact-request and session-scoped human approvals;
- immutable SQLite audit ledger with a SHA-256 hash chain;
- canonical, permit-gated filesystem operations;
- structured allowlisted shell execution;
- MCP stdio discovery/proxy with schema and identity drift checks;
- secret broker with scoped consumers and version-bound permits;
- GitHub REST adapter with separate action and credential authority;
- hardened React/Tauri control-plane preview;
- cross-boundary adversarial regression tests.

## Security boundaries

### MCP

Tool trust is bound to the provider, tool name, schema and descriptor identity. Discovery is refreshed immediately before forwarding so a tool cannot silently change after authorization.

### Secrets

Agent requests contain credential references rather than credential bytes. Material is exposed only inside the authorized consumer boundary. Rotating a secret invalidates permits created for the previous version.

### GitHub

Reads may be explicitly allowed by policy. Writes, branch creation and pull-request creation require human approval. File deletion and pull-request merge require a **one-time** human approval and reject reusable session grants.

### Audit

Material authorization and execution events are appended to an immutable SQLite ledger chained with SHA-256 hashes.

## Verification

The v0.1 gate runs:

- Rust formatting and clippy with warnings denied;
- the full Rust workspace test suite on Linux;
- the full Rust workspace test suite on Windows;
- React/TypeScript production build;
- Linux Tauri-host compile;
- adversarial regression tests as part of the workspace suite.

A green gate does not prove the absence of vulnerabilities. It demonstrates that the documented fail-closed invariants have executable regression coverage.

## Desktop preview

The desktop application is intentionally labelled as a **preview/control-plane surface**. The enforcement crates are real; v0.1 does not claim that every adapter is already live-wired through the GUI.

The Windows installer is not code-signed yet, so Windows may display a reputation warning.

## Known limitations

- no code signing or established SmartScreen reputation;
- no automatic updater;
- no cloud control plane or remote policy service;
- no claim of universal compatibility with every MCP client/server;
- secret storage at rest is supplied by the trusted local host rather than a dedicated OS-keychain implementation;
- the desktop UI is not yet the complete live operator console for all adapters;
- production deployment should use additional platform-native controls rather than treating Latch as the sole security boundary.

## License

MIT. Copyright © Purysho.

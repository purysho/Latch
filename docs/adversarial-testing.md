# Adversarial testing

Phase 11 treats untrusted model output, repository text, MCP metadata, credentials and remote mutations as separate attack surfaces.

## Regression matrix

| Attack / failure mode | Enforcement invariant | Automated evidence |
| --- | --- | --- |
| Prompt or document text says “ignore policy” | Policy evaluates typed operation + resource, not embedded instructions | `latch-adversarial::injected_text_cannot_grant_authority` |
| Approval request mutated after a human approves it | One-time approval is bound to the exact request fingerprint | `one_time_approval_is_bound_to_exact_request_fingerprint` |
| Credential rotates after authorization | Secret version is revalidated at execution | `secret_rotation_revokes_preexisting_execution_permit` |
| Reusable grant attempts destructive GitHub action | Delete/merge require one-time human approval | `destructive_github_action_rejects_reusable_session_grant` |
| MCP server impersonates a trusted provider | Provider identity is part of the trusted resource | `latch-mcp::spoofed_provider_with_same_tool_name_does_not_inherit_trust` |
| MCP schema/descriptor changes after authorization | Discovery is refreshed immediately before forwarding | `latch-mcp::schema_drift_between_authorization_and_forwarding_blocks_call` |
| MCP arguments violate schema | Invalid calls never reach upstream | `latch-mcp::invalid_arguments_never_reach_upstream` |
| MCP returns invalid structured output | Invalid output is withheld and audited | `latch-mcp::invalid_structured_output_is_withheld_after_forwarding` |
| Filesystem traversal / protected path | Canonical paths and protected-path checks fail closed | `latch-fs` adapter regression suite |
| Shell command smuggling / interpreter escape | Structured allowlisted command rules are revalidated before execution | `latch-shell` regression suite |
| Audit entries are modified or deleted | SQLite triggers + SHA-256 chain make the ledger append-only and verifiable | `latch-audit` regression suite |

## Release gate

The v0.1 CI gate requires:

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace` on Linux
4. `cargo test --workspace` on Windows
5. React/TypeScript production build
6. Tauri host `cargo check` on Linux with the native WebKit/AppIndicator dependencies installed

A green gate does not prove the absence of vulnerabilities. It demonstrates that the documented fail-closed invariants have executable regression coverage.

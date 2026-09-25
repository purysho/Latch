# ADR 0001 — Rust authorization core with Tauri desktop shell

- Status: Accepted
- Date: 2026-09-25

## Context

Latch is security infrastructure. Its authorization model must be deterministic, strongly typed, independently testable, local-first, and suitable for filesystem/process controls. The companion Witness app already establishes a Tauri + React desktop pattern in the Purysho tool family.

## Decision

Use Rust for the authorization core and trusted backend. Use Tauri 2 + React + TypeScript for the local desktop control plane.

The core crate must not depend on the UI or external adapters.

## Consequences

Positive:
- typed request/resource model
- memory-safe systems implementation
- natural Tauri integration
- single local desktop distribution path
- core tests do not require a browser or service

Trade-offs:
- slightly slower UI iteration than a Node-only backend
- MCP ecosystem integration may require additional Rust work later

This trade is accepted because authorization correctness is more important than prototype speed.

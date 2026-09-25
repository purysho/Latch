# ADR 0002 — Controlled process execution without an implicit shell

Status: accepted.

## Context

Phase 4 must allow useful developer commands while rejecting command injection and shell chaining. Passing an agent-provided string to a platform shell would make quoting and metacharacter interpretation part of the security boundary.

Timeouts must also account for descendants rather than only the direct process.

## Decision

Latch will:

- parse human-style command lines itself;
- convert requests to a command ID plus argv vector;
- map command IDs to trusted canonical executable paths;
- launch the executable directly;
- refuse common command-shell executables in V1;
- bind command configuration into a fingerprint;
- hash the configured executable and recheck it before execution;
- clear ambient environment inheritance unless the rule explicitly names variables;
- enforce canonical working-root scope;
- run with a mandatory timeout and bounded capture;
- use ProcessKit's private process containment for timeout teardown.

## Consequences

Positive:
- shell metacharacters are not an execution primitive;
- command policy is deterministic;
- request fingerprints bind argument vectors;
- descendant processes are covered by timeout containment;
- process output need not enter audit storage.

Tradeoffs:
- this is not an interactive terminal;
- some legitimate shell syntax is deliberately unavailable;
- allowed tools may themselves execute project code or child processes;
- executable upgrades require command-rule refresh because the hash changes.

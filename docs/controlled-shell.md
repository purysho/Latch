# Controlled process execution

Phase 4 introduces the latch-shell crate.

## Objective

The adapter supports developer commands without providing arbitrary shell authority.

The process flow is:

1. parse a command request as data;
2. map its command ID to trusted configuration;
3. validate the argument shape and working directory;
4. produce a canonical ActionRequest;
5. evaluate normal Latch policy;
6. mint an ExecutionPermit only for an exact ALLOW decision;
7. revalidate rule, executable and working directory;
8. append TOOL_FORWARDED;
9. launch the executable directly, never through an implicit shell;
10. enforce timeout and bounded capture;
11. append TOOL_RESULT.

## Command policy

A command rule binds a stable command ID to:

- canonical executable path;
- SHA-256 of the executable;
- argument policy;
- allowed canonical working roots;
- mandatory timeout;
- maximum captured-output bytes;
- explicitly inherited environment-variable names;
- fixed environment values owned by trusted configuration.

Any change to these fields changes the command-rule fingerprint and invalidates a request prepared against the older rule.

## Argument policy

V1 supports two modes:

- Any: every structured argv shape is permitted for that command;
- Exact: only explicitly listed argv vectors are permitted.

Any should be used sparingly. It is useful for commands such as a deliberately broad test runner, but it grants the executable freedom to interpret every supplied flag.

## Parsing

prepare_line uses a small structural parser. It understands whitespace plus single and double quotes, but rejects unquoted shell-control syntax including:

- ampersand;
- pipe;
- semicolon;
- redirection operators;
- backticks;
- caret;
- newlines;
- command substitution syntax beginning with dollar-parenthesis.

The parser never asks cmd.exe, PowerShell, sh or another shell to interpret the line.

prepare_argv exists for integrations that already possess structured arguments. In that path there is no shell grammar at all.

## Forbidden V1 command shells

Rules cannot register:

- sh / dash / bash / zsh / fish;
- cmd.exe;
- powershell.exe / pwsh;
- wsl.exe.

This is intentionally narrower than a general terminal. Language runtimes and build/test tools are not automatically safe; if configured, their argument policy must reflect the authority the user intends to grant.

## Process containment

The adapter uses ProcessKit for direct async process execution, capture and timeout handling. Each run is owned by a private process container so a timeout tears down the process tree rather than merely abandoning the direct child.

Standard input remains closed. Environment inheritance starts empty and only explicitly configured names are copied from the Latch process.

## Result capture and audit

The caller receives:

- exit code when one exists;
- timed-out flag;
- stdout;
- stderr;
- truncation flag;
- wall-clock duration.

Capture is bounded by the command rule. The audit ledger does not copy stdout or stderr. It records byte counts, SHA-256 digests, timeout/truncation state, duration and exit code.

## Security boundary

This phase is not a general sandbox.

If npm test is allowed and the package's test script invokes another executable, that behavior is part of the authority granted to npm test. Likewise pytest can execute repository test code and cargo test can execute Rust build/test code.

Latch Phase 4 prevents unauthorized command selection, argument shapes, shell chaining, working-directory escape, stale command configuration and executable replacement. Separate network and deeper sandbox controls are outside this phase.

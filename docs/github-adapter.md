# GitHub adapter

Phase 9 adds a remote GitHub execution boundary.

## Authority rules

| Action | Minimum Latch authority |
| --- | --- |
| Read file | explicit policy allow or stronger |
| Write file | human approval |
| Create branch | human approval |
| Create pull request | human approval |
| Delete file | one-time human approval |
| Merge pull request | one-time human approval |

A broad policy allow is deliberately insufficient for remote mutation. Destructive actions do not accept a reusable session grant.

## Credential flow

The adapter never owns a GitHub token.

1. The GitHub action receives its own `ExecutionPermit`.
2. A separate `secret.use` permit is issued for the `github-api` consumer.
3. The secret broker validates credential reference, consumer and version.
4. Credential material is exposed only inside the GitHub transport call.
5. The audit ledger records the GitHub action and credential reference, never token bytes.

The concrete `GithubRestTransport` uses the versioned GitHub REST API and can be replaced by a mock transport for deterministic tests.

## Operations

- `github.contents.read`
- `github.contents.write`
- `github.contents.delete`
- `github.branch.create`
- `github.pull.create`
- `github.pull.merge`

Repository paths, branch names and SHAs are validated before an authorization request is created.

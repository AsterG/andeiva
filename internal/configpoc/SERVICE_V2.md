# Authenticated configuration v2 adapter

ServiceV2 exposes the existing coordinator and catalogue to trusted adapters. It
opens an existing prepared store; it cannot create/migrate one, activate runtime,
execute preparatory begin/finish shortcuts or advertise a public capability.

Provisioned accounts may carry SubjectID and CredentialRevision together. Both
absent preserve legacy authentication, but cannot authorize v2. They are mirrors:
the canonical registry controls active identity, login and credential revision.
An account recreation needs a new identity; no identifier is derived from a name,
credential, OS UID or request body.

ResolveSession accepts a real session token and returns a redacted process-local
binding pinned to its Manager. Every service call revalidates logout, expiry,
idle timeout, role and account mirrors before acquiring the configuration lock.
Registry ownership/revocation is then checked under the same lock as the action.
Authentication and storage locks do not overlap. A logout after authentication
linearizes does not cancel an already admitted request; registry changes before
the action lock still reject it.

Administrators use namespaces/admission/execute/query/list/close; viewers retain
status/projection reads only. Returned values are detached copies. Credential
revisions, token material and binding internals are not response data. Legacy
clients remain unchanged. Local Services writes still require their separate
proof mapper and are denied in this adapter.

Reproduce with Go 1.27.4 and the existing dependencies:

```bash
go test -race ./internal/adminauth ./internal/configpoc -timeout 15m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

Tests cover issuer/TTL/logout/role/mirror changes, four registry changes across
eight entry points, concurrent revocation, cold reopen, foreign ownership and
Stage/Validate/Commit Confirmed/Confirm/Save/Rollback with simulated engines.
Native Debian unprivileged tests passed; no appliance service, real nftables rule
or public Web/CLI/API v2 endpoint is activated by these tests. Transport TLS,
origin/CSRF controls, atomic wire envelopes, opt-in cutover and storage continuity
remain integration gates. Logical budgets are not physical quotas.

[Español](SERVICE_V2_ES.md) · [Português](SERVICE_V2_PT.md)

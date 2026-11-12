# Prepared configuration operations transport

[Español](OPERATIONS_V2_ES.md) · [Português](OPERATIONS_V2_PT.md)

This increment qualifies a private HTTPS handler and Go client contract. The
production router and capability response remain unchanged: there is no public
v2 activation, retention guarantee, runtime cutover or new restriction on v1.

The prepared handler reuses the existing TLS, host/origin, session, CSRF and
client-surface checks. ServiceV2 revalidates the real session and canonical subject
registry on every request. Client-supplied identities and forwarding headers do
not grant permissions. Viewers cannot access the operation catalogue or mutate it.

Only the approved path families are handled:

- `POST /api/v2/config/operation-namespaces`
- `POST /api/v2/config/operations/admit`
- `POST /api/v2/config/operations/{id}/execute`
- `GET /api/v2/config/operations/{id}`
- `GET /api/v2/config/operations?namespace_id=...&state=...&cursor=...&limit=...`
- `POST /api/v2/config/operation-namespaces/{id}/close`

They are reachable only through the private prepared handler, not the production
constructor. There is no added status or evidence endpoint. Firewall operations
are stage, validate, commit, confirm, save, rollback and recover. `revoke` is
rejected before admission because the coordinator does not implement it yet.
Local Service operations and their proof mapping remain unavailable here.

Request/reply bodies are bounded to 1 MiB. Unknown/duplicate JSON members,
noncanonical decimal strings and untrusted ID/path fragments are rejected.
New uint64 wire values, including both generation counters, are decimal strings.
Operation results retain their historical outcome; `current` separately contains
the global lineage/generation and domain projection captured under the same
storage lock. Empty/filtered pages also carry `current`. The v2 `snapshot.revoked`
list contains durable retired subject IDs, not imported legacy usernames.

Cold-migration wrappers inspect existing locked v1 sources without replay or
cleanup. Preparation requires explicit subjects, legacy ownership bindings and
source fingerprints checked again under both source locks. It preserves source
journals and selects only prepared storage; it neither enables runtime operations
nor chooses operational Running without coordinator readback.

## Reproduce

Use Go 1.27.4 on Linux from the repository root. Tests create temporary journals
and verified loopback HTTPS listeners; no root, appliance connection or real
network namespace/firewall modification is required.

```sh
go test -race ./internal/adminapi ./internal/adminclient ./internal/configpoc -run '^(TestPreparedOperationsV2.*|TestOperationsV2.*|TestMigrationServiceV2.*|TestServiceV2AtomicObservations|TestServiceV2Observations.*)$' -count=1 -timeout=10m
go test ./cmd/... ./internal/... -count=1 -timeout=10m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

The HTTPS handler tests use real v1 journals, explicit cold migration, the real
v2 store and **simulated engines**. They exercise confirmed commit, confirmation,
Save, rollback, historical/current responses, empty pages, RBAC, ownership,
concurrency and hostile requests. Client tests use labelled wire fixtures; they
do not establish an end-to-end production client/runtime deployment.

Native Debian 13 unprivileged qualification measured these complete focal test
processes, including setup and TLS where applicable:

| Process | Elapsed | CPU | Cgroup memory peak |
|---|---:|---:|---:|
| Prepared HTTPS handler | 0.997485 s | 0.233278 s | 15,028,224 B |
| Store/migration observations | 0.360537 s | 0.138744 s | 12,849,152 B |
| Client wire fixtures | 0.182327 s | 0.098538 s | 13,606,912 B |

Cgroup memory is not process RSS or production service overhead. These checks do
not qualify 5,000 real-engine cycles, physical capacity/retention, power loss,
protected reclamation, Web/CLI/API parity or runtime cutover. Storage release
gates remain open. Public routing and activation require their separate gates.

# Prepared Local Services v2 proof mapping

This is a pure resolver and an ephemeral proof book. It does not enable local
configuration operations, HTTP/SSH routes, privileged IPC, runtime migration or
appliance changes. Existing v1 behavior is unchanged. The v2 coordinator still
rejects Local Services transitions; tests construct explicit mapping snapshots.

`configpoc.ResolveLocalProofV2` checks the stored operation fingerprint, namespace,
subject incarnation, expected global generation and canonical component revisions.
The composite schema5 hash remains distinct from the schema3 local hash. Confirm
requires the actual pending origin, owner, lease, deadline and pinned origin outcome.
Commit/rollback before lease allocation have an explicitly empty lease, bound to
the exact operation and target. No fake keys or leases are created. Final/pending
operation replay remains an observation; it is not remapped to fresh evidence.
An inactive foreign-domain Candidate may retain an older Base after boot. It is
preserved unchanged and does not block local mapping. Local Validate/Commit reject
a stale local Base with a conflict; the resolver never rebases a Candidate.

Input is a trusted internal copy, not a DTO or authorization grant. Domain
snapshots omit Pending; separate confirmation/origin fields carry that binding.
Historical local revisions require a previously verified retained global witness;
the pure resolver does not establish provenance. It performs no I/O or effects.
It returns an opaque scope with copy-only access to its canonical target.

`PreparedProofBookV2` reuses existing limits and pure local profile/listener helpers:
256 outstanding tokens, 20 seconds for recovery, 60 seconds for managed endpoints,
also limited by the execution window and pending deadline. Only token hashes are
stored in memory. Recovery evidence requires the exact authenticated session;
managed endpoints may use another session of the same durable subject/credential
incarnation. Endpoint proofs bind the registered run, namespace, instance and
local ActivationHash. A replacement listener at the same address is not equivalent.
Web/API labels can share one HTTPS receiver; labels confer no authority.

Managed issuance requires a published pending projection and actual receiver
registrations. The trusted caller must prove those observations first: Publish
does not inspect the kernel. All enabled bindings require one distinct endpoint
proof; all-disabled confirmation still requires recovery evidence. Reservation is
atomic and single-use. Invalid evidence cannot permanently block the book. Tokens
are invalidated on runtime drift, close or process replacement and never persisted.

## Required integration boundary

Authenticate a real E1 SessionBinding before acquiring the coordinator lock.
ProofIdentityV2 is only the immediate authentication observation, never a cached
capability. Under the same store lock, revalidate subject retirement/credential
revision, exact operation, generation and mapping, then reserve. The proof book
must never reacquire auth or coordinator locks. Lock order is auth (released),
store, proof book. No copied-snapshot/reservation gap is permitted in integration.
The book does not automatically revoke an already copied identity observation;
tests reauthenticate at each action boundary after logout/revocation. Caching or
reusing that observation for later actions would violate this contract. Nil,
uninitialized, incomplete and closed books reject calls without panicking. Internal
evidence/identity/reservation values omit secrets from JSON and diagnostic formatting.

Consume after durable intent admission, including uncertain publication; release
only when the coordinator proves admission had no effects. Replay must not reuse
old tokens. Publish only after verified readback and durable pending selection;
invalidate before activation/recovery. Apply must never synchronously wait for a
proof request. Existing guards own all effects and autonomous safety recovery.

These requirements are not yet wired. No Local Services v2 capability, local
rollback implementation or downgrade guarantee is added here. The prepared book
is not an additional active runtime budget. This does not close storage exhaustion,
protected audit retention, physical quota or garbage-collection requirements.

## Validation

Tests use real session authentication with generated temporary credentials and
explicit pure-mapper snapshots. They cover hash/generation/owner/fingerprint
mismatch, replay refusal, pending publication, stale listener instances, same-user
new-session endpoints, exact-session recovery, revoked/foreign sessions, expiry,
capacity, atomic reservation, single use and concurrent reservation. They do not
claim real HTTPS/SSH connectivity, kernel readback or Debian appliance execution.

```sh
go test -race ./internal/configpoc ./internal/localadmin
go vet ./internal/configpoc ./internal/localadmin
go test ./internal/configpoc ./internal/localadmin -run '^$' \
  -bench 'Benchmark(LocalProofV2|PreparedLocalProofV2)' -benchmem
```

Run with the pinned Go toolchain and preprovisioned module cache; dependencies are
unchanged. Native resource and end-to-end integration qualification remain pending.
No Docker, EKS/Helm, process, listener or deployment configuration changes.

A 500 ms developer WSL/Linux benchmark measured resolver 107455 ns/op,
25369 B/op, 267 allocations; recovery Issue+Reserve+consume measured 91345 ns/op,
20159 B/op, 222 allocations with an empty book, and 94743 ns/op, 20157 B/op,
222 allocations with 255 retained entries. Authentication is outside that loop.
The sample binding encoded to 703 bytes and its target to 750 bytes; these are
fixture sizes, not maximum live memory or appliance sizing. The 256-entry bound
is tested separately. No native workload or performance guarantee is implied.

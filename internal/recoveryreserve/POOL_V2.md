# Prepared reserve lifecycle, profile v2

This internal library adds exact claims, immutable one-time payloads and reusable preallocated slots. It does not select configuration, authenticate an administrator, prove archive membership or activate an appliance service. R1 constructors, bytes and APIs remain unchanged; each reader rejects the other pool format.

`PrepareV2` requires an empty private descriptor root and a fixed admission, plan or emergency role. `OpenV2` retains the existing manifest flock and pinned file identities; the caller retains ownership of the directory descriptor. Profiles permit 1–32 slots and aligned 4 KiB–1 MiB payloads. Each bank has a 4 KiB header and separate preallocated extents. Lifecycle calls create no files, truncate no allocation and delete no paths. A partial preparation is retained, never cleaned automatically.

For the prepared R2 18-slot profile, use `ClaimClass`: ordinary slots 0–7, closing slots 8–15 and autonomous system slots 16–17. Invalid profiles/classes are refused. Orphans consume only their class; no borrowing or automatic orphan release occurs. Generic `Claim` is a lower-level primitive and must not be used by the R2 admission assembly. Canonical catalogue, namespace and byte/inode closing credits remain a separate required integration.

`WriteOnce` binds a payload to an exact typed scope and returns its immutable `BindingV2`. An exact retry is idempotent; changed bytes/scope conflict. `ReadBound` requires the exact latest valid binding, never an older fallback. `InspectClaimed` returns a copied candidate plus exact binding, not a selected result. Scope hashes normalize deadline instants to UTC. Claims/bindings redact ordinary formatting but intentionally serialize full internal metadata; public DTOs must exclude these types.

`RetireCAS` requires an exact claim/binding and structured scope/finality/archive/Current/Previous proof. The **coordinator must validate actual canonical selection, archive bytes, dependencies and lease resolution under its store lock**. The pool validates structure, scope hash, identity and CAS; arbitrary valid-looking hashes do not independently prove that an archive exists. Never deserialize a retirement proof from an administration request. There is no pool callback into a store or authentication manager.

Retirement advances both banks through retired-held, free-prepared and ready, synchronizing and verifying both at each phase. Only an identical ready pair is allocatable. A recognized interrupted phase can resume only with the exact original proof. A stale proof cannot affect a newly claimed epoch. Torn/unknown banks fail closed without repair, fallback promotion or allocation. Claimed pre-admission orphans remain held; repeated crashes can exhaust that finite class.

The pool uses no worker, timer, network access or engine application. Filesystem preallocation does not guarantee metadata/journal/COW behavior, quotas, read-only/media failures or power-loss durability. Tests using process exits are not power-loss tests. Protected capsule archival, lease finality, v2 replay/selection, physical category isolation and runtime continuity are not implemented by this library. AND-01/02 remain open.

## Reproduce

With Go 1.27.4 and dependencies already available on Linux:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/recoveryreserve -count=1 -timeout=4m
go vet ./internal/recoveryreserve
go build ./cmd/... ./internal/...
```

Tests use real temporary preallocated files and synthetic coordinator retirement proofs. They cover over 64 reuse cycles, partition exhaustion, exact scopes/epochs, simultaneous callers, fault boundaries, actual process exits, corrupt banks, identity/permissions and refusal of R1/V2 cross-loading. They do not qualify a real configuration archive, kernel rollback or native ENOSPC for this v2 implementation. Native resource and finite-volume qualification remain pending.
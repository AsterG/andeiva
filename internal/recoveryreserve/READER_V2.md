# Prepared read-only reserve access

This library implements an explicit shared-reader filesystem profile and bounded
observations of reserve v2 pools. It does not enable grouped IPC, select policy,
authorize effects, migrate an appliance, or complete storage resilience.

`PrepareV2` and `OpenV2` retain the private 0700/0600 profile. R1 and durable pool
record formats are unchanged. `PrepareSharedV2` accepts only an empty, previously
provisioned directory; `OpenSharedV2` keeps the exclusive writer lock. Neither
converts existing permissions. New files are created exclusively and set to 0640
even with umask 077; a failed preparation preserves partial files for inspection.

The trusted supervisor supplies `ReaderAccessV2` version 1: owner UID, dedicated
reader GID, device and directory inode. Directories must be exactly 02750, files
0640, with the expected owner/group and no extended/default POSIX ACL. File
identity, single link, regular type and same device are checked; unsupported ACL
queries fail closed. The reader must be non-root and belong to the reader group.
Accounts, credentials and TLS keys must remain outside these roots/groups.

`OpenReadOnlyV2` also requires the expected pool ID, role, capacity and slot count.
It opens read-only descriptors without flock, sync, repair or publication.
`Snapshot` compares two bounded captures, including both banks and payloads;
`Revalidate` compares a later capture with the original evidence. Valid unequal
banks retain the existing v2 transition semantics; torn, inconsistent or changing
evidence is rejected. Returned inventories/payloads are copies. A snapshot has
private fields and is not a serializable authorization token.

`CheckDirectory` and `ReadFile` reuse the same filesystem checks for selected-state
loaders. `ReadFile` accepts only a bounded ASCII basename and a caller limit of
1 byte to 1 MiB. It does not validate content hashes or contextual graph edges.

The caller must verify the canonical sticky opt-in, selected state, typed work,
finality and reserve bindings. Keep the coordinator publication barrier across
verification and effects; the supervisor must fence an old controller before a
new writer opens. Double reading is not disk/kernel CAS. An already armed guardian
must retain its verified rollback plan independently of further store reads.
Cancellation is cooperative, not a hard filesystem deadline. Offline conversion,
old-binary qualification and real three-UID permission tests remain integration
gates; no automatic conversion or private-profile fallback is provided.

Resource bounds follow the existing pool limits: at most 32 slots of 1 MiB,
`slots + 1` retained file descriptors, and one transient directory descriptor.
Two captures can retain four payload copies per slot; callers must budget retained
snapshots. No worker, timer, cache, disk allocation or background I/O is added by
the reader. The normal 18-slot plan profile uses 16 KiB per slot. Benchmark results
are library measurements, not appliance sizing or worst-case latency guarantees.

An unprivileged WSL/Linux run with Go 1.27.4 on an Intel i7-1370P measured ten
snapshots of a full 18-slot, 16 KiB plan pool: 2.241 ms/op, 1,377,323 B/op and
7,493 allocations/op. Allocation totals are not process RSS. Debian isolation,
appliance overhead and the full GroupIPC transaction remain unmeasured here.

Reproduce on Linux with Go 1.27.4 under a non-root account and a filesystem with
POSIX ACL support. Tests use disposable directories, not an active store:

```sh
go test -race ./internal/recoveryreserve -count=1 -timeout=3m
go vet ./internal/recoveryreserve
go test ./internal/recoveryreserve -run '^$' -bench BenchmarkReadOnlyV2Snapshot -benchtime=10x
```

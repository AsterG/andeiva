# Transaction recovery reserves

This internal v2 path is not enabled by the installed administrative runtime.
It does not activate interfaces, forwarding or NAT.

## Authority and lifecycle

One selected v2 configuration store remains authoritative. Trusted assembly opens
three distinct preallocated pools: admission (4096-byte payload), plan (16384) and
emergency (8192), each with 18 slots partitioned into eight ordinary, eight
confirmation-closing and two system slots. Callers cannot choose paths or slots.
Profile and physical identity checks precede effects.

Admission binds the durable operation, subject incarnation, domain, generations
and request fingerprint. A selected intent and verified plan precede component
application. An emergency capsule records uncertainty; it never makes a revision
Running or confirms an operation. Missing or uncertain resources fence writes.
Independent helper deadlines remain responsible for reverting unconfirmed work.

A canonical archive preserves exact capsule bytes, terminal operation/recovery
facts and audit references. Its inline payload is limited to 56 KiB and its entire
serialized object to 64 KiB. A bundle index authenticates Lineage+Owner; every
lookup also compares the complete claim or binding. An unused closing escrow can
prove ownership but cannot supply an invented binding or operation.

Physical reuse requires the same complete archive in both actual selected roots,
validated finality and exact pool/slot/epoch/bank compare-and-swap. The archive and
protected audit remain retained. Partial retirement resumes from those facts;
unknown claims are held, not deleted by a filename or prefix match. Reclamation
inspection follows typed audit, snapshot, operation and recovery edges.

## Capacity and limits

Logical bytes/inodes reserved in the canonical catalogue are not RAM allocation,
a paid credit, a disk quota or proof of physical free space. A potential confirmed
commit holds separate closing capacity until its terminal archive and retirement
are complete. This does not raise a caller's configured storage budget.

The complete ordinary lifecycle must fit the existing 16 MiB/64-inode envelope,
including archive publication, temporary objects and partial-finalization recovery.
Budget admission and failure qualification are still under development; the
presence of the pool primitive alone does not close storage-exhaustion resilience.
Do not enable this path in appliance assembly until that qualification passes.

## Reproduce source checks

With Go matching go.mod and an authorized dependency cache:

```sh
go test -race ./internal/recoveryreserve ./internal/configpoc -count=1 -timeout=15m
go vet ./internal/recoveryreserve ./internal/configpoc
go build ./...
```

`TestReserveCoordinator*` uses real temporary journals/pools and simulated engines.
`TestReserveArchiveV2*` exercises archive bounds, identity substitution and missing
or foreign audit edges. Process-exit tests are not physical power-loss tests.
Native finite-filesystem pressure and real-engine runtime acceptance must be
reported separately. No production availability, HA or arbitrary hardware-failure
guarantee is established by these tests.

The authorized copied-volume harness also accepts
`--authorized-debian-v2-reserve-volumes`, with the same seven arguments as
`--authorized-debian-v2-volumes` in the [storage guide](../storagevol/README.md).
Build the test executable with `go test -c ./internal/configpoc`. This explicit
mode prepares recovery pools inside the copied configuration volume and requires
both the normal RUN/PASS evidence and `ANDEIVA_NATIVE_R2_CASE_PASS` per case.
It tests ordinary admission, reads/replay and release after byte/inode exhaustion
or an open deleted filler. Its 128 MiB filesystem must reject a confirmed commit
whose separate closing capacity cannot fit. This is not qualification of lease
closing under exhaustion, a complete coordinator restart, or real traffic engines.

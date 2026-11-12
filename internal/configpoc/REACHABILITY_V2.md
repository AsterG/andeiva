# Read-only v2 reference inspection

[Español](REACHABILITY_V2_ES.md) · [Português](REACHABILITY_V2_PT.md)

This internal inspector checks the known reference closure of a selected v2
store within explicit work budgets. It is not connected to a runtime, public
API or CLI. It does not open a coordinator, apply policy, recover transactions,
delete files or produce a list of reclamation candidates.

## Access and result

`inspectReachabilityV2` receives an already opened `os.Root`, a context and a
`v2ReachabilityBudget`. On Linux it opens the existing `checkpoint.lock` read-only
and acquires a nonblocking exclusive lock. A missing or busy lock is an error;
the inspector never creates it. Root and file identity, ownership, permissions,
type and filesystem are checked. The directory remains private; inspection does
not broaden permissions. Other platforms reject the storage inspection.

The inspector enumerates directory entries in bounded batches and validates the
selected pair and the required bounded selection segments. It follows typed
references through state, operation indexes, migration records, configuration,
audit, recovery and verified witnesses. Reads validate content hashes and strict
JSON shapes. It rechecks the selector and pinned directory/lock identity before
returning success. It does not call `openV2` or run its recovery and cleanup paths.

`Complete=true` means the known closure was checked within the supplied budgets
and the observed selection remained consistent. It does **not** establish file
deletion eligibility, export acknowledgement, a durable GC mark or available
recovery space. Unreferenced files must not be treated as garbage from this
report. Opaque audit payloads remain opaque protected leaves.

Cancellation, exhausted budgets, missing references, malformed content,
unsupported reference shapes or inconsistent identities return an error and
`Complete=false`. Partial counters are diagnostic progress, not a usable safety
mark. A later write makes the report a historical observation; it is not a lock
or authorization that a future collector can reuse.

## Reference semantics

A hash has meaning in its field's contract. A semantic revision identity is not
automatically the filename of an object containing a `Revision` wrapper.
Embedded configurations are validated in their containing objects. External
canonical payloads are followed only through the existing typed producer and
consumer rules. Recovery-index keys are not object references.

Traversal keeps edge context: index level and prefix, selected state, witness
purpose and the relevant identity relationships. Reusing an object hash or a
previously visited node does not permit skipping validation in another context.
An unresolved or incompatible context prevents a complete report.

## Resource limits

The caller supplies limits for directory entries, unique objects, edges, I/O
calls, total bytes read, active payload bytes and traversal depth. The inspector
rejects invalid budgets and stops when work exceeds an admitted limit. Object
and edge tracking remain in memory and are bounded by those limits.

`PeakActiveBytes` measures accounted payload bytes; it is not total Go heap,
process RSS, filesystem cache or a physical storage reservation. Necessary
descriptor cleanup still runs when work stops. Context cancellation is
cooperative between filesystem operations; it cannot interrupt a stalled kernel
read or promise a hard wall-clock deadline.

This implementation is not qualification for a 674,000-inode retained history.
Large-store traversal needs separate external-memory work and measurements.
Appliance CPU, RAM, disk-I/O and service-latency benchmarks remain pending.

## Reproduction and limits of evidence

From the repository root on Linux/WSL with Go 1.27.4 and dependencies already
available locally:

```sh
GOPROXY=off GOSUMDB=off go test -race -mod=readonly -buildvcs=false ./internal/configpoc -run '^TestV2Reachability' -count=1 -timeout=5m
go vet -mod=readonly -buildvcs=false ./internal/configpoc
go build -mod=readonly -buildvcs=false ./internal/configpoc
```

The focused tests use temporary real stores and simulated engines. They cover
unchanged journal content and engine-call counts, prepared and staged states,
commit/confirmation and boot references, missing/busy/replaced locks, budget and
cancellation failures, malformed/foreign files, migration read accounting,
edge-context validation and opaque audit payloads. No privileged operation or
live appliance is needed for this suite.

These tests do not establish real dataplane continuity, OS reboot or power-loss
behavior, physical quotas/reserves, safe reclamation or production performance.
No protected export/acknowledgement or deletion capability is enabled. AND-01/02
and runtime activation remain separate, open qualification gates.

Native Debian 13 AMD64 qualification as UID 1000 without capabilities passed the complete TestV2Reachability selection: elapsed 0.449149 s, CPU 0.229975 s, cgroup memory peak 13,561,856 B. Fixtures use real temporary journals and simulated engines to prepare state; inspection does not call engines. No real kernel policy, listener or appliance state was changed. Cgroup memory includes test/cache costs and is not daemon RSS or a capacity guarantee. Full configpoc race, vet/build, cross-compilation, SAST and secret checks passed; independent source review found no remaining C/H/M. This evidence does not qualify GC, reserves or AND-01/02.

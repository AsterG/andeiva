# Anonymous authentication observations

This is a prepared, opt-in Linux storage component. It is not enabled by an
appliance runtime. The ordinary `adminauth.New` constructor retains its existing
protected audit behavior. [Español](README_ES.md) · [Português](README_PT.md).

`adminauth.NewWithAnonymousObservations` changes classification only for new
login failures before credential verification. It aggregates these failures by
UTC minute and the receiving transport's actual socket peer. IPv4-mapped IPv6
addresses normalize to IPv4; ports, forwarded headers, usernames, credentials
and tokens are not observation keys. Internal attempts without a socket and
invalid peers use an unattributed overflow count. This slice does not add
observation hooks to other unauthenticated API failures.

Successful verification, verified login rate/session-limit denials, logout,
revocation and administrative denials continue through protected audit. Its
existing failure latch remains fail-closed. Anonymous storage failure does not
turn failed authentication into success and does not latch protected audit as
failed. Historic protected events, including old login denials, are never
reclassified or modified. No protected export, acknowledgment or deletion
authority is introduced.

## Admission and ownership

The trusted assembler supplies an already opened, dedicated `os.Root`, owned by
the process with mode 0700, and a mandatory `AdmissionGuard`. `Prepare` requires
an empty area. It writes versioned snapshot/policy files, syncs them, then
atomically selects `policy.json`. `Open` requires this explicit selection and an
existing exclusive lock. Files are regular, single-link, owner-only 0600 files;
unknown entries, symlinks, malformed data and unsupported versions are rejected.
The caller owns the root descriptor; `Store.Close` joins its worker and releases
its lock, returning publication errors.

`AdmissionGuard.Selection` must enforce the real runtime compatibility selection,
quiescence during preparation, byte-identical historic protected inventory and
backup, and exclusion of incompatible writers. After admission it must verify
the exact active selection. Hashes identify the captured historic inventory,
not a requirement to prohibit new protected audit appends. The package provides
no permissive guard and no deployed guard implementation. A new directory or
policy file alone cannot prevent an old binary from ignoring the migration.
Runtime wiring must reject unsupported selections before constructing writers;
that qualification remains pending. Constructor refusal tests exercise the seam,
not a deployed old executable.

`AdmissionGuard.Capacity` must qualify isolation from protected audit/recovery
allocations. Observed filesystem availability and separate directories do not
create that isolation. No quota, allocation reservation or protected reserve is
implemented here.

If ordinary `Open` cannot recover the anonymous area, `OpenDegraded` accepts only
an exact canonical `Selection` supplied by independent trusted runtime state,
validated by the guard against the real area identity and compatible selection.
It never infers selection from corrupt observation files. It opens no data files,
starts no worker and cannot write, delete or repair them. New observations remain
bounded in memory, with `memory_only`, `degraded` and `unknown_gap` explicit;
`allocated_known=false` and zero `persisted_through` avoid invented measurements
or history. Verified authentication still uses mandatory protected audit. Missing
or unsupported canonical selection fails admission; there is no legacy fallback.

## Bounds, publication and loss

- At most 1,440 retained intervals and 512 peer-minute entries in total. Extra
  source detail goes to the interval overflow counter; retained totals continue.
- Detail expires 24 hours after interval creation. Cardinality eviction can
  shorten coverage. Expired and capacity-evicted observation counts are visible.
- The owned-area ceiling is 4 MiB; snapshots are bounded to 512 KiB. Linux block
  accounting includes named files and the directory. Publication preflights
  coexistence with a temporary plus 64 KiB metadata allowance, available blocks
  and an inode. These observations are not a filesystem quota, a guarantee
  against concurrent external allocation, or complete filesystem overhead.
- A minute worker flushes only dirty data and schedules expiry. `Record` performs
  no filesystem I/O. Disabled legacy auth has no observation worker.
- Publication uses a new temporary, file/directory sync and rename. An uncertain
  write result blocks further publication until reopening. A valid unselected
  next-generation temporary can be removed on reopen; a malformed or partial
  temporary is preserved and reopening fails. Selected file drift is rejected.

Reports are lower bounds, not exact crash ledgers. `persisted_through` identifies
the last acknowledged publication; `pending`, `unknown_gap`, `degraded`, overflow
and saturating loss counters expose limitations. Every reopen conservatively
reports an unknown gap. Counters cannot reconstruct lost unsynced attempts.
Expired detail is excluded from reads even under pressure. Physical removal
cannot be guaranteed while stopped or read-only; cleanup resumes only when safe
publication is possible. Context cancellation is cooperative, not a hard deadline
for filesystem calls. Corrupt selection or I/O integrity failures are not cleared
by treating the store as empty.

Expiry depends on trusted UTC wall-clock time. A backward clock rejects new
observations or marks the report degraded; this does not prove 24 hours of real
elapsed time across reboot or clock faults. Clock qualification remains required.

`Manager.AnonymousObservations` requires a valid admin session and grants only
read access. It adds no HTTP route or write permission. Web/CLI/API activation,
actual volume-pressure tests, reserve qualification and appliance performance
remain outside this prepared slice. AND01/AND02 are not closed by this component.

## Reproduce and measured scope

From the repository root, with Go 1.27.4 and preprovisioned dependencies:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -race -mod=readonly -buildvcs=false ./internal/authobservations ./internal/adminauth -count=3
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go vet -mod=readonly -buildvcs=false ./internal/authobservations ./internal/adminauth
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go build -mod=readonly -buildvcs=false ./internal/authobservations ./internal/adminauth
go test -mod=readonly -buildvcs=false ./internal/authobservations -run TestObservationsBoundedResourceSample -bench BenchmarkObservationsExistingPeer -benchmem -v
```

Tests cover default protected-event compatibility, admission, admin/viewer
authorization, concurrency, pressure through an injected guard, cardinality,
age/clock boundaries, selected-file drift, interrupted publication and child
process exit/reopen, including audited verified login with a corrupt observation
snapshot and independently admitted memory-only collection. They do not simulate physical power loss or qualify a
deployed storage reserve. One Linux/WSL sample retained 1,440 intervals and 512
peer-minute entries in a 175,945-byte snapshot, with 184,320 observed allocated
bytes. The existing-peer microbenchmark measured 116.2 ns/op, 16 B/op and one
allocation/op on that host. These are component measurements, not appliance
RAM, continuous throughput or production sizing guarantees.

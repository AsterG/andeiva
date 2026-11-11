# Verified journal reads: observations and limits

This preparation retains the last durable state and lightweight metadata with
validated audit. Historical configurations are read and checked on demand. It
does not compact, expire or delete journal records or receipts, or repair an
exhausted store. The public v1 format, authorization and retry semantics remain.

## Reproduction

Use the repository's Go toolchain on Linux, without privileges or real engines:

```sh
go test -race -count=1 ./cmd/... ./internal/...
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
ANDEIVA_STORE_PROFILE=1 go test -run '^TestStoreReadResourceProfile$' -count=1 -v ./internal/configpoc
go test -run '^$' -bench '^BenchmarkStoreRead' -benchtime=1x -count=1 -benchmem ./internal/configpoc
```

Resource profiles are opt-in. They create synthetic valid journals and run a test
subprocess; they do not fill a filesystem, change interfaces or invoke nftables.
The child measures service reopen, including two expected resume records.
`BenchmarkStoreReadOpen` measures the file-store open instead, without those
service writes. Filesystem caches may be warm. Neither is physical cold I/O,
appliance boot time or a traffic benchmark.

## Measured comparison

Linux AMD64 under WSL, Go1.27.4, same fixture SHA-256 values. Baseline source:
`3d0ddb1aff2f09f63d7a327c459a32bb0d99e05c`, with only the profiling test overlaid.
The after measurement uses this preparation. Values are observations, not RSS
limits, statistically established latency targets or supported-platform promises.

| Fixture | Records before reopen | Journal bytes | Retained heap before | Retained heap after |
| --- | ---: | ---: | ---: | ---: |
| Small | 8 | 7,184 | 73,720 | 65,248 |
| Record limit | 2,046 | 1,858,643 | 1,435,720 | 1,096,160 |
| Large configuration states | 524 | 64,078,216 | 65,646,680 | 755,256 |
| Large legacy audit | 517 | 63,992,020 | 63,912,352 | 63,851,736 |

Retained heap is the instrumented difference after GC with the service kept alive.
For large configuration states, subprocess peak RSS changed from129,552,384 to
13,475,840 bytes. This is the maximum of the child process, not memory exclusively
attributable to Open. Cumulative allocated bytes did not improve in that case:
770,898,080 before versus778,014,168 after. Complete startup validation still runs.

One-iteration file-store benchmarks for that fixture observed891ms before versus
948ms after. History remains validated metadata in memory, about23 versus16us.
Revision lookup now verifies disk and observed0.030ms/480B before versus
5.307ms/1,500,352B after. These are different operations and individual samples;
do not compare them as the same measurement or a general performance guarantee.

The audit-heavy case intentionally shows that legacy audit strings have no small
individual size cap. Keeping audit metadata can still retain substantial memory.
The journal's existing aggregate bound remains; no universal1MiB heap claim is made.
Synthetic records and receipts are not evidence of5,000 complete transaction cycles.

## Failure coverage and remaining gates

Tests cover unchanged v1 journal bytes, full receipt serialization/replay, file
identity/permissions/size/hash changes, no partial historical result, authorization
before reads, rejection before guard/engine effects and new writes blocked after
an integrity failure. Pending rollback is checked under the service mutex before
a status request can itself trigger expiry. Linux uses nonblocking, non-following
opens; FIFO replacement before lookup is rejected. The precise replacement interval
between metadata inspection and open is not claimed as an induced physical race.

Full-module race, vet/build, static analysis and Windows/Darwin compile-only checks
passed in the development environment. Linux runtime tests do not prove behavior
on those other systems. Independent source review found no blocking issue in the
bounded preparation. Real full-volume ENOSPC/EDQUOT/inode/EROFS, protected audit
retention/export, checkpoints, migration, sustained transaction cycles and permanent
dataplane continuity remain separate gates. AND01 and persistent AND02 stay open.

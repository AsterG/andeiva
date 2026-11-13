# Selected action-authority reader

The selected helper reader defaults to the existing complete G1 history walk.
`SelectionReaderOptionsV2.Policy = SelectionActionAuthorityV2` is an explicit
trusted assembly opt-in. No runtime factory selects it in this increment.
It is not an API, request, environment, or IPC capability flag.

The opt-in validates the existing complete bounded selection/header/state segment
with `readSelection`, then walks the current action authority closure: canonical
configuration and payloads, Candidate evidence, keyed current operation/witness
references, protected audit leaves, RoutedWork and its baseline/boundary,
current recovery records, and every live reserve. A successful exact reserve
archive lookup additionally walks its typed FinalWork, operation/recovery audit,
plan and configuration dependencies. Opaque catalogue audit cannot authorize
an action. Independent purpose, identity, original deadline, pool snapshot and
physical readback/CAS checks remain mandatory.

Historical configuration snapshots are descriptions, not new selections. Their
payloads, canonical shape and audit tip are checked; their inherited historical
witness trees and recovery pointers are not recursively enumerated. Their
`Intent` must be absent. A Pending descriptor in an intended target is not
independent authority: the current selected Intent/Pending validators establish
its context. A saved Startup witness already has explicit provenance handling;
this increment adds no exception to it.

Every object read in this mode is retained through the final check. The existing
FD cache is unchanged. When it cannot retain an FD, the call retains bounded
original bytes and filesystem identity, then reopens and compares both before
returning authority. Neither descriptor pressure nor the raw-buffer cap allows
an untracked dependency. The same active-byte budget charges these buffers and
a conservative 512-byte bookkeeping allowance per dependency. The combined
raw/bookkeeping allowance is at most half that existing budget; the remaining
budget covers decoding and final comparisons. Cancellation, byte/object/IO
exhaustion or changed content, inode, ownership, link count, ACL or permissions
fails closed. Cleanup releases all retained resources even on rejection.

This policy deliberately does not establish integrity of unrelated retained
history. Full G1 remains required for retention/GC, cold activation, and bounded
background integrity checks. A durable corruption latch and its scheduling must
be integrated and independently reviewed before enabling the policy in a live
runtime. This increment does not claim that integration, the fixed three-second
RPC performance gate, kernel traffic, native execution, or production readiness.

Reproduce the focused Linux tests from a trusted checkout with the pinned Go
version and cached dependencies:

```sh
go test -race ./internal/configpoc -run TestActionReaderV2 -count=1
go test -race ./internal/configpoc -run TestSelectedReaderV2 -count=1
go test -race ./internal/configpoc -run TestSelectedCacheV2 -count=1
go vet ./internal/configpoc
go build ./...
```

Tests use real temporary configuration/pool stores and filesystem reads, with
simulated/preparation-only engines. A differential test removes a retained
historical object reached by full G1 but outside the current action closure:
the action read succeeds without requesting it and full G1 still rejects it.
This is a scope assertion, not permission to reclaim that object.

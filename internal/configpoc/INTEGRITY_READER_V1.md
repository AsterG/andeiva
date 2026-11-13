# Selected-store integrity inspection

`CaptureReferenceV1` reads and revalidates the bounded selected header, including during existing recovery. Its tuple is correlation, not authorization or readiness. `InspectionReference` additionally rejects a configuration with Intent, Pending, or RecoveryRequired. Neither method walks the full historical closure.

`InspectQuiescentV1` accepts only the default full-history reader. It checks the exact expected tuple and quiescence before G1, runs the existing complete graph and reserve validators, then revalidates the selector, pinned records, directory profile and all three reserve-pool snapshots. Action-only readers cannot report a complete inspection.

The caller must hold the API writer/publication barrier throughout inspection and independently verify that the helper guardian is idle or in bootstrap. The reader takes no writer lock and cannot enforce that external protocol. Accepted operations and potential closing escrow are allowed while the configuration is quiescent; inspection validates their retained claims without executing, expiring, releasing, or resetting them. This avoids requiring caller retries before startup inspection can complete.

Only `complete` with a nil error qualifies the inspected tuple. Cancellation, stale correlation and unavailable data do not qualify it. A successful bounded immutable-record read followed by failed hash/canonical decoding records per-call corruption evidence; it yields `fenced` only after unchanged selector and reserve/profile revalidation. Unknown errors, budget exhaustion, missing records, and inaccessible profiles remain unavailable. The reader neither persists nor clears the helper's fence.

All existing graph, bytes, descriptor and I/O bounds remain in force. Error classification reuses the same graph budget rather than starting another scan. No cache survives the call. Cancellation is cooperative; it cannot impose a hard deadline on a blocked filesystem operation. No file publication, cleanup, engine call, or garbage-collection authority is introduced.

Linux tests use real temporary stores and reserve pools with simulated engines. They cover accepted work, potential escrow, real pending/intent boundaries, full-policy enforcement, stale tuples, cancellation, corrupt history, profile failures, budgets and unchanged files. They do not qualify a deployed helper, native multi-user isolation, performance targets, or the whole integrity scheduler.

With Go 1.27.4 and pre-provisioned offline dependencies:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc -run '^TestIntegrityReaderV1' -count=1 -timeout=3m
GOPROXY=off GOSUMDB=off go vet ./internal/configpoc
```

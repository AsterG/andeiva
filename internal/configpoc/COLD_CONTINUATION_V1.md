# Bounded cold continuation

`CaptureColdAnchorV1` captures a canonical selected header and returns an opaque, in-process `RoutedColdAnchorV1` tied to that reader. `Reference()` exposes correlation only; JSON encoding does not expose its private contents. Capture does not qualify history or declare readiness.

`ResolveColdContinuationV1` independently validates the current action closure and reloads the original anchor selection/state through the existing bounded, profile-checked reader. It checks work identity, original deadline, purpose and durable predecessor links. It permits only existing compensation/confirmation/readback, resume of established work, and a coordinator Boot linked to the captured configuration or its verified completion. New ordinary Arm/Apply remain denied until full inspection qualifies the runtime.

A Boot boundary must retain the exact source configuration, original work and origin/old-Boot references. A subsequent Boot after pending rollback additionally requires the real final recovery record, owner/origin/lease, exact rollback projection, audit chain and contextual recovery-index entry. Failed ordinary completion uses its immutable operation, selected plan and final audit. The entire resulting configuration is compared, including Startup and candidates. Matching Running hashes do not establish lineage. Boot deadlines remain the original Started + 10 seconds; no caller duration or reset is introduced.

The caller still holds the writer barrier and performs actual guardian receipt CAS/readback. This library neither inspects physical listeners nor replaces full G1. The selected-state size limit bounds the retained encoded anchor; it is not a heap quota. All additional reads consume the existing per-call graph and I/O budgets. No descriptors or object cache are retained between calls by the anchor.

Tests use real temporary canonical stores/pools and simulated physical replies. Pending recovery followed by Boot is covered. Integration of an interrupted ordinary Intent remains blocked separately by existing R2 retirement rejecting a leased plan with no archived lease resolution after failed rollback; the private reproduction is tracked by the integrator. The reader does not bypass that refusal, and cold-Intent runtime completion is not qualified by these tests.

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc -run '^TestColdContinuationV1' -count=1 -timeout=3m
```

Use Go 1.27.4 with offline dependencies already present. No deployed runtime, network or multi-user performance qualification is claimed.


## Persistent fence

ResolveFencedContinuationV1 reuses the same bounded action graph and final revalidation. It permits original compensation and readback; it rejects Arm, Apply, Bootstrap and Resume. Confirm requires an already selected Confirm or boot Intent whose complete typed content still matches the captured Intent. A Pending-only anchor cannot authorize a newly admitted Confirm while fenced. This does not clear a fence or qualify full integrity. Confirmed corruption also blocks the entire writer, including internal identity and maintenance publications.

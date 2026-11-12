# Selected configuration reader

This opt-in library connects a dedicated read-only identity to the existing v2 configuration and reserve records. It does not start a helper, install permissions, expose an administrative endpoint or grant network authority.

## Filesystem profile and migration

Private storage remains directories `0700` and files `0600`. `PrepareSharedReaderV2` requires a quiescent selected configuration, records the sticky `shared_reader.v1` feature and fences the private handle. It does not change existing permissions. The private opener rejects that marker; the shared opener requires it. Older strict readers reject the unknown feature before opening engines.

A separately qualified offline conversion must preserve every existing byte and hash, establish a supervisor-pinned owner and dedicated reader group, directories `02750`, records `0640`, and the writer lock `0600`. There is no automatic conversion or downgrade. Shared creation changes the mode only of a newly created exclusive inode. Exact descriptor checks reject ACLs, links, unexpected ownership, group, mode, device or root inode. Credentials and TLS private material belong outside these roots.

## Selected authority

`NewRoutedSelectionReaderV2` borrows the store root and three read-only reserve pools. Its identity and access policy come from trusted supervisor assembly, never request JSON. `Observe` returns correlation containing the selected pair, state hash, lineage, sequence, global generation and work hash. `Resolve` compares that complete reference with a fresh read and returns the existing opaque selected plan only for the requested action. A work hash alone is insufficient.

The reader reuses canonical selection, migration, G1 closure, routed work and reserve checks. It takes no writer flock, performs no cleanup or publication, and calls no engine. Both pool banks and selected metadata are captured and revalidated. Arm/apply require the selected activation intent; confirm requires its selected confirmation or boot intent; compensation/recovery requires its selected intent. Final active state permits resume and readback, never an unrelated recovery. The original boot deadline and guardian receipt remain authoritative.

`PrepareView` returns selected current/startup bundles and retained baseline inputs. These are preparation inputs, not observations of actual interfaces or listeners. Physical preparation must obtain its own live readback. The supervisor must enforce a single-writer incarnation barrier through the eventual effect and fence old handlers before replacing the writer. Repeated disk reads alone are not atomic disk/kernel CAS.

## Bounds and reclamation

Explicit object, edge, depth, I/O, byte and active-payload budgets bound each traversal. Cancellation is cooperative between filesystem operations, not a hard deadline for stalled kernel I/O. Pool captures remain bounded by the existing slot/capacity profile. Immutable objects are hash checked; semantic revisions are not guessed as filenames.

G2 retains its existing process-local provenance ledger, writer mutex/flock and complete mark-before-sweep rules. Only its metadata checks and directory sync use the shared profile. No protected deletion, historical adoption, new GC authority or durable reclamation database is introduced. Reopen loses session-only deletion authority.

## Reproduce

With Go 1.27.4 and a pre-provisioned module cache, run on Linux as a non-root user:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc ./internal/recoveryreserve -run 'TestSharedProfileV2|TestSelectedReaderV2|TestReadOnlyV2Metadata' -count=1 -timeout=3m
go vet ./internal/configpoc ./internal/recoveryreserve
go build ./cmd/... ./internal/...
```

Tests use actual temporary records, explicit fixture permission conversion and selected coordinator intents; preparation/effects are test doubles. They do not establish three-identity appliance integration, host networking, full IPC availability or crash-safe installation. Native integration and resource measurements must be reported separately.

A ten-iteration WSL/Go 1.27.4 sample of `Observe` over a temporary migrated fixture measured 20.737 ms/op, 7,885,193 B/op and 62,973 allocations/op. This includes G1 and reserve capture/revalidation. These are allocation volume and fixture latency, not retained heap, appliance RSS, throughput or a production sizing target.

## Verification reuse within one call

`PrepareCurrentView` and `ResolveCurrent` derive a fresh complete selection under the reader mutex. The latter treats work hash, lineage and **work-scope** generation as expectations; this generation is not the selected global generation. Existing methods still enforce the caller's complete selection reference. No wire format or deadline changes.

Only a single call can reuse verified object bytes: at most 256 retained read-only descriptors and half the existing active-payload budget. Every typed decode and contextual edge check remains in place. Before returning, the reader rechecks named ownership/modes/ACLs, retained inode identity and timestamps, exact bytes, the selector and both banks of each reserve pool. Object replacement, unlink, in-place changes and cancellation fail closed. No cache survives a call.

G1 may reuse an identical snapshot, intent or recovery validation only with the complete canonical state and all other validation arguments in its key. Pure configuration and boot-target predicates retain exact input identities. At most eight immutable routed-work results can be reused, only when every source object remains pinned; their represented payload is charged against one quarter of the existing active-payload budget. The final selected plan is reconstructed separately, with current purpose, identity and reserve checks. Cache limits cause ordinary bounded reads, not partial authority. These limits bound descriptors and payloads, not total Go heap or appliance RSS.

Run the focused negative checks with Go 1.27.4:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc -run 'TestSelectedCacheV2|TestSelectedReaderV2' -count=1 -timeout=4m -benchtime=3x
```

This reduces repeated verification; it does not remove retained history, increase traversal budgets, extend the three-second helper deadline or qualify appliance performance.

A WSL/Go 1.27.4 compiled-test sample completed the shared-store lifecycle, including schema-4/schema-6 transactions, helper restart and rollback, with real temporary records, reserve pools and Unix IPC and simulated physical engines. With `RLIMIT_NOFILE=256`, the full test took 22.96 s; its final confirmation read took 1.7016 s. The previous reader timed out at Validate6 after 3.0007 s. These runs execute different numbers of successful steps and are not a throughput comparison.

The successful compiled process used 22.95 s user CPU, 5.02 s system CPU and 29,192 KiB peak RSS. The fixture holds both writer and helper-side pools in one process, unlike the intended separate helper. It is not a Debian appliance measurement or a guarantee for growing retained history. Race tests validate behavior separately from this non-race timing sample.

The effective cache cap is `min(256, RLIMIT_NOFILE/2, currently_free_FDs-32)`. A bounded Linux descriptor census is only a capacity hint; failure disables descriptor caching. General object reads can occupy half that cap, leaving room for dependencies of routed-work validation. Neither the process limit nor traversal budgets increase. Descriptor exhaustion denies authority; releasing unrelated descriptors permits a subsequent fresh read. The original work-loader wrapper and R2 finality validator retain their behavior; only G1 supplies memoized pure configuration predicates and immutable-work loads, while rechecking complete invocation state and finality.

Three subsequent full cycles passed with both soft and hard descriptor limits fixed at 256 and independently observed through `/proc`. Across 60 source calls, the maximum was 1.8702 s. Aggregate elapsed time was 76.5586 s, user/system CPU 85.2268/17.6873 s, and peak RSS 36,156 KiB. Sampling descriptors every 10 ms observed a peak of 204; sampling does not prove the instantaneous peak. This repeated one-process WSL fixture remains distinct from native separate-process qualification.

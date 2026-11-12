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

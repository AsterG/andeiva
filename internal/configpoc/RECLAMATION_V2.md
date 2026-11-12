# Prepared reclamation of newly created index pages

This internal, explicit opt-in slice reclaims only operation-index pages created exclusively by the current writer after opt-in. It has no runtime, API, CLI, timer or startup binding. It does not reclaim protected audit, retained operations, configurations, migration evidence or historical files. AND01/02 remain open.

The implementation deliberately narrows durable garbage collection to the lifetime of one writer. A fixed ledger holds at most 1,024 page identities in memory. Exhaustion leaves additional pages held and does not block ordinary operations. Generic object use and deduplication remove reclamation authority even if later publication fails. Reopening loses the entire ledger; filenames, hashes and the opt-in marker do not reconstruct it. There is no historical adoption or resumed deletion batch.

`enableIndexReclamation` selects optional `reclamation_version: 1` before tracking begins. Zero is omitted and preserves the default encoding. Other values are rejected. Publication and predecessor validation reject removal or downgrade of the marker; Boot and migration/reopen tests cover preservation. The existing strict prior reader rejects the new field. Do not downgrade an opted-in store by deleting the field. There is no new database or per-write durable provenance list.

`reclaimIndexPages` holds the same store mutex and exclusive writer lease for the complete bounded walk and sweep. It reuses the typed reference walker, including contextual edge validation, selected/predecessor segments, receipts and recovery dependencies. An incomplete closure authorizes no deletion. A complete closure alone is still insufficient: a candidate also needs this writer's exclusive-creation identity and unchanged regular-file, owner, mode, device/inode, link-count, size and content checks. All names are generated internally relative to the retained directory descriptor.

Every removed page is independently eligible; process exit between removals does not require resuming a batch. Remaining pages become held on reopen. I/O or integrity ambiguity fences the handle; cancellation or an exhausted inspection budget stops work without clearing an existing fence. The implementation refuses maintenance during configuration intent, pending confirmation or recovery-required state.

Named bytes/inodes removed are not free filesystem blocks. Accounting is reconciled after directory synchronization, and ordinary admission still observes filesystem capacity. A deleted file held open can retain its allocation. This slice is not a quota, recovery reserve, protected export acknowledgement or physical-failure guarantee.

The private directory and one cooperating writer are essential. Linux does not supply a general compare-inode-and-unlink operation; these checks do not defeat a malicious owner/root rewriting names concurrently. The scan holds the mutex and can delay requests. Context cancellation is cooperative between filesystem calls, not a hard deadline for stalled I/O. G1's bounded in-memory walker is not qualification for a 674,000-file store. Concurrent GC with a complete creation/deduplication/protection/pin barrier remains separate work.

## Verification

Use Go 1.27.4 on Linux/WSL with a pre-provisioned module cache:

```sh
GOPROXY=off GOSUMDB=off go test -race ./internal/configpoc -run '^TestV2Reclaim' -count=1 -timeout=4m -v
GOPROXY=off GOSUMDB=off go vet ./internal/configpoc
GOPROXY=off GOSUMDB=off go build ./cmd/... ./internal/...
```

Tests exercise real temporary files, retained replay, bounded tracking, migration, Boot, identity/link replacements, interruption before/after unlink and sync, process exits and deleted-open files. Injected admission shortage is distinct from native ENOSPC/EDQUOT qualification. The old-reader test explicitly skips unless supplied a prior-source binary; a skipped test is not compatibility evidence.

For exact prior-source compatibility, extract commit `79fcc63a5b9fb88e5e5988e2c5f33739fde7f52a` into a fresh temporary source directory. Copy only `store_v2_reclaim_prior_linux_test.go` into its `internal/configpoc` directory, build that package with `go test -c -o /absolute/path/prior-configpoc.test`, then run the current test:

```sh
go test -race ./internal/configpoc -run '^TestV2ReclaimOldReaderCompatibility$' -count=1 \
  -reclaim-old-reader=/absolute/path/prior-configpoc.test
```

The adapter calls the actual previous source's `openV2`. The test checks that default stores remain readable and opted-in stores are rejected after 130 further publications, with no file changes.

An initial WSL race fixture of 40 catalogue cycles removed 180 pages / 93,720 named bytes while retaining 180 tracked pages and exact replay. One measured lock interval was 1.114 seconds. This is a storage-test sample, not freed-block evidence, appliance performance or a production sizing claim.

The exact Linux test binaries were subsequently run on Debian as UID 1000 with NoNewPrivileges and PrivateNetwork. The suite, including the real prior-reader argument, passed against temporary real journals. Combined elapsed time was 2.060528 seconds, CPU time 0.830340 seconds and cgroup peak memory 20,893,696 bytes; these describe the complete test workload, not appliance RSS or a continuous benchmark. No active datastore was touched. Process-exit tests do not establish power-loss safety. Native finite-volume pressure and full runtime continuity remain separate gates. Independent source review found no critical, high or medium findings in this prepared scope.

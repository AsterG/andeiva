# Cold upgrade of a prepared migration

`PrepareOfflineMigratedRoutedStoreV3` upgrades only a private store already prepared by `PrepareMigrationV2`. It preserves the migration object, source journal records, receipt indexes, explicit subject bindings, lineage and generations. It does not replace existing configuration, copy history again, change permissions or invoke an engine.

The bounded initial profile requires schema 4 firewall policy and schema 3 local services with deny default, no forwarding rules, services or interfaces. Both source domains must have equal Running, Startup and LastGood, with no Candidate, pending transaction or recovery requirement. Nonempty firewall rules are preserved. Other states require their existing authorized recovery or administration flow; they are not silently rebased or discarded.

## Source authority and publication

The installer supplies pinned destination and source roots, the two explicit legacy fingerprints, the existing three R2 pools, a storage budget and a trusted `OfflineMigrationReadbackV3` implementation. The core locks firewall, local services and destination in that order. It rereads both sources under their existing locks, checks fingerprints against the copied migration, and holds those locks through verification, publication and destination close. Changed sources fail before readback. The installer must also keep the old administration writer stopped and the observed helper namespace pinned throughout the call.

`VerifyMigratedSources` receives copied, canonical revisions from the validated migration. Its production implementation must inspect the former helper's actual firewall policy and establish absence of resources belonging to the declared inactive local-service domain. Foreign listeners are neither adopted nor evidence of ANDEIVA service activity. A reported hash, caller JSON, a boolean or a simulated engine is not source verification. The callback cannot reenter the destination store while its writer lock is held.

One publication selects schema 7 configuration, source verification audit and witness, R2, guard deadlines, the shared-reader profile and `configuration.routed-offline-migration.v1`. The source witness does **not** verify the new gateway. Opening the coordinator requires routed authority, a trusted boot ID, real reserve pools and absolute guard deadlines; readiness still requires physical Boot and readback. G1 uses its normal witness and migration validation, without a new unverified-history exception. Unsupported readers reject the required feature; it cannot be removed by subsequent publication.

## Interruption and rollback

Before selector publication, the original migration remains selected. Unselected immutable objects can remain. An interrupted `selection.pending` preserves the existing recovery fence and cannot be silently retried. After selector replacement, a lost acknowledgement is an uncertain successful selection: reopen only with the intended shared filesystem profile and perform normal integrity and physical boot recovery. Never remove the marker or rewrite imported history to downgrade. Keep source backups and failed preparation evidence; an operator may prepare another independent destination through the authorized migration process. This function does not perform offline profile conversion or provide an automatic rollback installer.

## Validation and limits

With Go 1.27.4, the focused command is:

```sh
go test -race ./internal/configpoc -run '^TestOfflineMigratedRoutedV3' -count=1 -timeout=2m
go vet ./internal/configpoc
go build ./...
```

The compatibility case requires `-args -reclaim-old-reader=/absolute/path/prior-configpoc.test`. Build the preceding production source with only `offline_routed_migration_prior_linux_test.go` added as its standalone test adapter. The test first proves that binary can read the original private migration, then requires rejection through its **shared** reader after the new feature is selected. Omitting the binary explicitly skips that compatibility case.

Tests cover real journal and pool files, replay, source locks, concurrent preparation, canonical input copies, complete G1 closure, missing runtime requirements, verification refusal, cancellation, interrupted publication and reopen. Their verifier is deliberately a unit test double; these tests do not qualify a native old-helper verifier or an appliance cutover. No host changes, physical policy application, storage reclamation, quota guarantee, power-loss guarantee or production performance claim is made. The measured fixture publication added seven files and 5,839 logical bytes in 22.3 ms on WSL; this is neither RAM usage nor allocated/free disk space, and does not include whole migration preparation. Native resource qualification remains separate.

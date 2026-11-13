# Prepared absolute helper deadlines

The additive internal v2 operations `arm_until`, `apply_scoped` and
`confirm_scoped` preserve an exact canonical UTC deadline. Scoped apply,
confirmation and existing recovery compare ID, previous/target hashes and the
original deadline inside the guardian mutex. A replacement receipt, including
the same ID/hashes with a deadline differing by one nanosecond, is foreign.

`NewPreparedAbsoluteGuardedEngine` requires a complete typed absolute authority.
The existing relative adapter has no `ArmUntil` method. Old helpers reject the
new verbs; the adapter never retries with a relative TTL. No public Web/CLI/API
field or runtime activation is added.

The guardian checks its own clock after potentially slow readback and derives
one independent monotonic expiry from the remaining interval. New leases need
at least 500 ms and at most the existing maximum TTL. An exact surviving receipt
can be rebound with less than 500 ms left without rearming it. Controller
cancellation/disconnection does not cancel the helper timer. Controller restart
can rebind the surviving exact receipt; helper restart loses RAM state and needs
the existing journal/bootstrap recovery. It never rearms implicitly.

Validation: run `go test -race ./internal/nftguardian ./internal/firewalladmin
./internal/firewallipc ./internal/previewruntime`, `go vet` on the same packages,
and `go build ./...`. Linux socket tests use unprivileged socket pairs and SIM
engines. They do not qualify real nftables, power loss, boot integration or
production deployment. Integration with the prepared storage v2 Boot deadline
gate remains separate.

The coordinator passes selected `Pending.Deadline` directly for Commit Confirmed,
Confirm and expiry recovery. Boot keeps its existing Started + 10 s authority.
A restarted adapter recovers expired receipts only through
`RecoverPreviousUntil` with the exact durable scope.

Trusted, prepared assembly may opt in using `v2CoordinatorOptions.GuardDeadlines`.
For immediate effectful Commit/Rollback/Recover it selects optional canonical
`Intent.guard_deadline` and sticky feature `configuration.guard-deadline.v1` in
one publication, before helper effects. The ten-second window starts after
validation, immediately before selecting Intent. Admission's Accepted/ExecuteBefore
and mutable store Clock never replace it. Request fields and revision hashes are
unchanged; there is no public activation flag.

Cold opt-in refuses unresolved legacy immediate Intents without inventing their
start time. Old readers reject the new feature; new assembly must retain opt-in
even after the Intent completes. Confirmed and Boot Intents reject a duplicate
`guard_deadline`. Exact deadlines remain in physical PlanIntent and typed archive
closure. R2 limits remain 16 MiB/64 ordinary inodes, 128 KiB metadata core and
256 KiB objects; admission includes feature/descriptor overhead and refuses
insufficient headroom before physical claims.

Without opt-in, unsupported absolute immediate operations are refused before new
objects/Intent/helper effects; an already admitted operation remains accepted and
the store stays available. Relative legacy assembly is unchanged. A helper that
already confirmed an ambiguous interrupted operation is never blindly rolled
back or falsely published as Running: the existing recovery fence remains.
Tests use real temporary stores, helper code and sockets with SIM engines. No
runtime cutover, Startup adapter, real traffic, power-loss or production claim is
introduced by this opt-in contract.

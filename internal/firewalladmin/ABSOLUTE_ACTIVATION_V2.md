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

The coordinator passes the selected `Pending.Deadline` directly for Commit
Confirmed, Confirm and scoped restart/expiry recovery. A restarted adapter can
recover an expired receipt only with `RecoverPreviousUntil` and that exact
durable scope. Immediate guarded Commit/Rollback/Recover lack a durable effect
deadline in the current format and remain explicitly gated before new objects,
Intent publication and helper Arm/Apply. Admission may already have been
journaled: the operation stays accepted and the store remains available.
Stage, Validate and Save metadata remain available.
Neither admission timestamps nor mutable store clocks are repurposed.

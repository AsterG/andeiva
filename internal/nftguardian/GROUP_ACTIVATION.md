# Typed routed group authority

`NewGroup(GroupEngine)` accepts the approved `RoutedActivationBundleV1` and
`RoutedTransitionV1` directly. It shares Guardian's private lease/timer/CAS core;
it never packs a composite into `configpoc.Revision` or creates component leases.
Legacy Guardian APIs and State wire fields retain their original meanings.

Trusted assembly supplies a real GroupEngine. Its mandatory `ValidatePlan` must
verify the selected durable intent, original deadline, lineage, contextual object
closure and reservations before any timer/effect. Shape/hash equality is not
authorization. No always-successful/default validator or runtime flag is provided.

`BootstrapStartup(ctx, transition, target, originalStarted)` requires a verified
physical `BeforeOwned`, with no effective configuration hash. It computes only
`originalStarted + 10s`, arms the rollback authority first and applies the target
under that deadline. It does not claim selected PreviousRunning was applied.
`State.Previous` is empty for this cold physical baseline; its artifact digest
stays separate from configuration hashes. The Root coordinator must select the
real plan and resources before calling it. Existing R2/legacy bootstrap fences
are untouched; the relative legacy bootstrap adapter is not made compatible.

`ArmUntil` binds an already verified complete previous/target pair and artifact
scope. `ApplyLease`, `ConfirmLease`, `RecoverLease` and `MatchObserved` compare the
stored transition and exact receipt. One Confirm requires full target-owned and
configuration readback. An exact confirmed receipt reconciles a lost reply;
recovery cannot blindly roll back a confirmed group. Rollback uses the exact owned
before artifact under an independent bounded context; failed readback fences it.

The engine's Current/ObserveOwned must read actual component state. The engine
must own all network/firewall/local writers and use deny-first apply/restore order.
The facade does not supply that engine, IPC, coordinator activation, kernel
commands, endpoint proofs or recovery storage. Its lease state is in memory;
helper-loss recovery still requires the Root's durable-plan/recovery integration.
No standalone database, catalogue, journal or unverified durable success is added.

```sh
go test -race ./internal/nftguardian ./internal/firewalladmin ./internal/firewallipc ./internal/previewruntime -count=3 -timeout=4m
go vet ./internal/nftguardian ./internal/firewalladmin ./internal/firewallipc ./internal/previewruntime
go build ./cmd/... ./internal/...
```

Group unit tests use typed real canonical bundles and controlled engine results;
they do not qualify physical multi-component activation. Native runtime, endpoint,
resource and process-loss qualification remain pending. No host/manager/DHCP,
inspection, uninterrupted-service, HA or appliance-release claim is made.

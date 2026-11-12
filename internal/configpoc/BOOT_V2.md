# Prepared v2 Startup recovery

[Español](BOOT_V2_ES.md) · [Português](BOOT_V2_PT.md)

This is an internal, inactive coordinator path. No production service, public
API, CLI, boot marker or privileged IPC binding enables it. It requires an
already initialized v2 configuration; it does not bypass migration readback.

A trusted, validated boot UUID distinguishes OS boot from process restart.
Process restart retains Running and resolves interrupted or unconfirmed work
through its existing operation and lease. A new OS boot selects the saved
Startup content only after validation and readback of every component. Startup
itself is unchanged; domain and global generations advance monotonically.
Candidate retains its owner, original base and revision, without application or
implicit rebasing. A stale base requires explicit restaging before Commit.

The boot transition persists its intent, bounded accounting allowance and sticky
`boot_startup.v1` required feature before engine effects. Its recovery record has
no fabricated user, admission receipt or confirmation origin. Completion selects
Running, the linked audit and a validated completed-boot reference together.
Reopening the same completed boot verifies effective state without repeating
effects or publication, including the completion-before-external-marker gap.
Older strict v2 readers reject the required feature; it remains present after journal
checkpoints. Nil optional fields preserve the previous encoding and hashes.

The prepared bootstrap adapter uses the existing one-time guardian operation;
ordinary Apply still needs an exact lease. It rejects foreign leases and checks
effective state after lost replies. The typed scoped recovery callback has no
privileged IPC binding yet. An unresolved or partial boot keeps the previous
selected Running and requires the same boot context to resume; it never invents
a verified revision. Do not downgrade or strip a selected required feature.

**Local Services Running different from Startup is rejected before effects.**
Its listener/evidence mapper remains pending F. No domain is silently skipped.
Do not enable this path in an appliance until runtime assembly, authenticated
helper binding, local-service recovery and native OS-boot tests are qualified.

## Reproduction

With Go 1.27.4 on Linux, from the repository root:

```sh
go test -race ./internal/configpoc ./internal/firewalladmin -run '^(TestV2Boot|TestPreparedStartup)' -count=1 -timeout=5m
go test -race ./internal/configpoc ./internal/firewalladmin ./internal/nftguardian -count=1 -timeout=10m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

Tests use real temporary journals, simulated engines and an in-process guardian.
Child-process exits test interruption around intent, component effects, readback
and selection. They cover repeated boot, pending confirmation, inactive Candidate,
UUID/record errors, a missing completion reference, logical budget rejection and
old-reader rejection beyond 64 selections. They do not test real nftables,
listeners, IPC, reboot, power loss or physical storage reservation. No privileged
operation is required. Native Debian 13 qualification as UID 1000 passed every
selected test without skips: coordinator elapsed 2.764573 s, CPU 1.307027 s,
cgroup peak 23,281,664 B; startup adapter elapsed 0.042477 s, CPU 0.014056 s,
cgroup peak 5,341,184 B. These are test-process measurements, not RSS or appliance
runtime overhead. Boot UUIDs were injected test inputs; real journals and actual
child-process exits used persistent simulated engines. No OS reboot, real IPC
or power-loss behavior was qualified.
AND-01/02 and production activation remain open.

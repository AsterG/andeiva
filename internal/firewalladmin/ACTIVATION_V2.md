# Prepared v2 activation guards

[Español](ACTIVATION_V2_ES.md) · [Português](ACTIVATION_V2_PT.md)

This adapter is preparation, not runtime activation. Production routing,
authentication configuration, privileged IPC messages and namespace scope are
unchanged. Real runtime assembly must use the guarded wrapper; plain Engine
fixtures continue to represent simulations only.

`PreparedGuardedEngine` reuses Engine, ActivationGuard and the existing
LeaseAuthority State/Current/Arm/Confirm contract. Its trusted recovery callback
uses the existing helper recovery operation. No caller-selected executable,
revision path, new privileged verb or administrative bypass is introduced.

The coordinator persists its exact intent before arming the helper. Immediate
changes bind the lease to that operation; confirmed commits use their persisted
lease. Apply requires the exact armed scope. All component readbacks precede
confirmation and outcome publication. Lost replies require an exact observed
receipt, lease and revisions, never an idle phase alone. Unchanged-policy commits
also establish a real lease receipt.

Rebinding an existing pending lease does not rearm or extend it, including during
the final 500 ms. Creating a new lease still requires at least 500 ms. Helper
timeouts do not depend on a live API process, session or subject.

Rollback uses the helper's existing recovery operation only after validating the
exact lease/previous/target and effective state. A failed confirmation can recover
after a verified helper rollback: configuration content returns to the previous
revision, domain/global counters advance, Startup remains unchanged, and the
failed confirmation outcome, linked audit and origin pin release are selected
atomically. The original commit outcome is not rewritten.

If the helper already confirmed the target but coordinator publication is
uncertain, this adapter fences writes and does not invent rollback or success.
Reopen remains unavailable until a separately qualified recovery resolves that
case. Unknown staging and unrelated helper leases are not cleared.

## Qualification

From the repository root with Go 1.27.4:

```sh
go test -race ./internal/firewalladmin -run '^TestPreparedGuard' -count=1 -timeout=5m
go test -race ./internal/firewalladmin ./internal/configpoc -count=1 -timeout=10m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
```

The Linux integration tests use real v1 journals, explicit cold migration and the
real v2 coordinator with the existing restricted guardian and **simulated
engines**. They test immediate/confirmed commits, late confirmation, lost replies,
partial apply, foreign leases, independent timeout, repeated reopen and an actual
staging-file collision after remote confirmation. They require no root, real
firewall rules or appliance connection. Native Debian 13 qualification ran all 10 selected guard tests without skips as
UID 1000 with no capabilities: elapsed 0.586653 s, CPU 0.273888 s and cgroup
memory peak 12,656,640 B. The guardian ran in-process with simulated engines and
real temporary journals. This is test-process consumption, not RSS or production
service overhead; it does not qualify real privileged IPC.

This does not qualify privileged IPC/runtime assembly, real nftables traffic,
Local Services evidence mapping, true OS-boot Startup application, physical
storage guarantees or power-loss resilience. OS boot must remain distinct from
process restart; that additional transition is not implemented here. AND-01/02
and runtime activation gates remain open.

# Routed activation artifacts

`OwnedV1` records exact prepared IPv4 state and explicit presence of the three
fixed legacy, routed and local tables. Present tables require complete canonical
schema 4, 6 and 3 revisions respectively; absent tables require a nil revision.
Local absence concerns only listeners owned by this manager in its retained
namespace. It says nothing about host SSH, HTTPS or other managers' listeners.

`DependenciesV1` binds the complete network plan to observed link facts, local
inventory and trusted neighbor declarations. Canonical objects are detached and
bounded to 256 KiB. `PreparedSnapshot` retains observed identity, MTU, flags,
IPv4 addresses and routes, bounded to 16 KiB. This first profile supports exactly
two planned links plus optional loopback and an empty IPv4 baseline. It refuses
foreign state, DHCP and arbitrary configured baselines.

Prepare and VerifyPrepared are read-only. ApplyPrepared compares the complete
baseline before effects; RestorePrepared removes only additions recorded by the
same executor, then verifies exact restoration under an independent bounded
compensation context. A snapshot or its hash grants no ownership. Ifindexes are
node-local witnesses, never authorization to adopt a link after reboot.

`New(Kernel, Network, localengine.Listeners, Options)` supplies the concrete Group
engine. Kernel is a trusted fixed-namespace transport restricted to the legacy,
routed and local tables; listener observation/retirement is manager-scoped.
Prepare returns `PreparationV1{Before, Target, Dependencies}` without effects.
Options.ResolvePlan must resolve those exact artifacts from selected durable
intent and validate original deadline, contextual refs and reservations. Shape
validation or an always-successful resolver is insufficient. `ObserveOwned` and
`MatchOwned` return/verify only selected refs after physical semantic readback.

Legacy fixture activation requires an actual known canonical schema-4 default-deny table, absent
routed table, empty IPv4 baseline and absent or known empty local table. One nft
transaction establishes routed/local deny and retires legacy enforcement before
route effects. Target rules replace deny only after network and owned listeners
verify. Recovery first installs deny, retires/restores owned listeners, restores
the exact network memento and atomically restores the previous tables, including
verified absence. Unknown or foreign readback fences instead of blind deletion.
This assumes exclusive writers in the retained namespace; it is not atomic against
an unrelated CAP_NET_ADMIN writer. Subsequent edits require the same network plan.

The trusted supervisor provisions the exact selected schema-4 revision, including
its existing rules, only inside the newly owned empty-IPv4 namespace. Full semantic
readback rejects missing rules even if a comment claims the selected hash; no
reset to an empty policy or adoption of an encountered table is permitted.

Inverse schema 6→4 requires Options.ResolveBaseline to resolve only the original
cold Work's saved bundle, actual BeforeOwned and dependencies. The one-hop durable
reference must retain original lineage and manager incarnation. Exact saved
firewall/local revisions and the complete prepared baseline are checked; absent
local state cannot impersonate enabled saved listeners. Under one confirmed lease,
deny precedes listener retirement and network restoration, then legacy enforcement
replaces routed enforcement atomically. Expiry reapplies the exact prior schema-6
network/listeners/rules under deny. A confirmed baseline can subsequently activate
the same owned network plan again. Prepare resolves the actual before/target side
after recovery instead of retaining an optimistic last-target selector.

Trusted helper-startup `RecoverPlan` resolves the authenticated original Work and
calls RecoverPrepared with its exact UID/GID/boot/run/target/host identity. Root
must verify lineage/generation, selected intent, finality and original lease/
deadline before returning artifacts. Only the same retained namespace incarnation
and exact baseline or full target are accepted after two network observations.
Mixed/foreign state fences without deletion. No fresh timer is armed and no
decision to undo a confirmed operation is made here. Reboot or a new namespace
requires controlled Boot establishment, never reuse of old ifindex authority.

No runtime flag, endpoint proof, complete durable recovery or host manager takeover is
provided. Trusted assembly must authenticate manager metadata and retained
descriptors. Helper restart cannot reconstruct executor ownership from the stored
snapshot alone. The module adds no database, workers or processes; it uses the
single Group lease, at most three known states per table and 512 KiB nft batches.
Controlled unit tests exercise compilers and faults. Native Debian 13 qualification
at source `f6a474f` passed TCP/UDP SNAT, tuple-bound related ICMP, IPv6 and
unsolicited-reverse denial, existing-flow revocation, no-NAT routing, and NAT
without forwarding authorization. The same run restored two saved schema4 rules,
reactivated schema6, reconciled a lost confirmation reply and reversed a confirmed
schema4 transition on its original timeout. All three namespaces were cleaned;
external addresses, routes, forwarding and nftables remained unchanged.
The complete qualification took approximately 45 s, 12.890886 s CPU and a
33,546,240-byte cgroup peak including child processes/cache. These are test costs,
not service RSS or throughput. The selected-witness fixture does not qualify
separate-process helper IPC, native Boot4, host interface takeover or Internet
access. Earlier evidence at `3918ad8` remains historical, not later-feature proof.

```sh
go test -race ./internal/networkexecutor ./internal/routedactivation -count=3
go vet ./internal/networkexecutor ./internal/routedactivation
```

No-network schema4 Boot uses `Options.ObservedBindings` from authenticated supervisor
inventory and `PrepareColdBoot(target4, saved4)`. It captures `ObservedSnapshot`
without a desired plan or plan hash, with actual absence of all three tables.
The selected Boot/SystemBundle and original Started+10s deadline must exist before
any apply. Schema4 apply/rollback writes only the legacy table; it performs no
address/route, listener or forwarding changes. Expiry restores actual absence,
not the prospective saved policy. Confirmed schema4 edits may differ from the
original saved policy while preserving the exact observed baseline. First schema6
activation compares that complete baseline with its real PreparedSnapshot;
inverse schema6→4 still requires the original authenticated saved baseline.
A fresh helper verifies the original scope and exact observed state through
RecoverObserved; it never adopts an encountered namespace or starts a new timer.
Tests use real compiler/readback, Group and durable coordinator/reserve code with
simulated kernel/network I/O. This is not native Boot4 qualification, configured
appliance interface management, DHCP or host takeover evidence.

Schema4 restoration now projects only the legacy revision from the exact
canonical target onto the original physical baseline. This preserves every
network/Observed/dependency fact and requires the original local revision.
`ProjectRoutedRestoreBaselineV1` is pure prospective data conversion, not proof
that the target is selected, saved or effective. Physical preparation may describe
such a target without effects. Validate/Recover still authenticate the exact
selected Work target, original scope/deadline and complete TargetOwned; the core
loader independently recomputes and compares that projection. Thus a schema4 edit
saved before schema6 can be restored exactly, while an unsaved edit can still
return to the older selected Startup4. The original Work.Baseline reference and
network memento remain retained; no new database, DTO or IPC field is added.
Changing local-service configuration or substituting a different physical memento
remains rejected. These tests model kernel/network I/O and do not qualify native
host configuration or DHCP.

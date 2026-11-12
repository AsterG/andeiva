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

Initial activation requires an actual known schema-4 empty deny table, absent
routed table, empty IPv4 baseline and absent or known empty local table. One nft
transaction establishes routed/local deny and retires legacy enforcement before
route effects. Target rules replace deny only after network and owned listeners
verify. Recovery first installs deny, retires/restores owned listeners, restores
the exact network memento and atomically restores the previous tables, including
verified absence. Unknown or foreign readback fences instead of blind deletion.
This assumes exclusive writers in the retained namespace; it is not atomic against
an unrelated CAP_NET_ADMIN writer. Subsequent edits require the same network plan.

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
Controlled unit tests exercise compilers and fault results. Native helper/traffic,
crash recovery, endpoint continuity and resource measurements remain pending.

```sh
go test -race ./internal/networkexecutor ./internal/routedactivation -count=3
go vet ./internal/networkexecutor ./internal/routedactivation
```

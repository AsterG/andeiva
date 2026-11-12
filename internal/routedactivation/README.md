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

These artifacts do not yet supply physical group activation, durable recovery,
endpoint proofs or runtime enablement. Trusted assembly must authenticate manager
metadata and retained descriptors; the coordinator must validate selected intent,
object context and reservation before effects. No second database is introduced.

```sh
go test -race ./internal/networkexecutor ./internal/routedactivation -count=3
go vet ./internal/networkexecutor ./internal/routedactivation
```

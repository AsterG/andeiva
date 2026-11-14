# Confined server component

Experimental, opt-in component; no production dispatcher, API, unit or selected
configuration writer calls it. `RunRoutedDHCPServerComponentV1` lives beside the
existing supervisor and reuses its namespace, executable, ACL, pidfd, cgroup and
descendant-drain primitives. [Español](docs/runtime.es.md) · [Português](docs/runtime.pt.md).

Trusted Root assembly must enter a dedicated process into the owned gateway and
a different mount namespace before calling it. It supplies actual host/gateway
namespace FDs, a readonly compiled-config FD (root:`_kea`, exactly 0440), a dedicated
`_kea` lease-directory FD, a storage byte budget, and a bounded context. Live LAN
addresses must match the compiler bindings. Both IPv4 and IPv6 forwarding must
already be zero. This does **not** block DHCP RAW sockets: keep laboratory clients
isolated until the explicit native process/socket observation. Product activation
still requires selected-policy authorization and a proved RAW-aware boundary.

The component makes mount propagation private; overlays `/run`, `/var/lib` and
`/etc/kea` with bounded tmpfs before creating any directories. It binds the
compiled file readonly to `/etc/kea/kea-dhcp4.conf` and the original persistent
lease directory to `/var/lib/kea`. These stock paths preserve Debian's AppArmor
profiles. It never creates missing directories in the host filesystem. The
compiler lease path is `/var/lib/kea/kea-leases4.csv`; an administrative revision
must never restore or overwrite operational leases.

The Root-owned `/run/lock` parent is `_kea` group 0750; engine directories are
0700. Ownership and exact modes are applied and verified through directory FDs,
so umask 077 cannot silently remove group traversal. Overlay parents use 0750
and `_kea` group. The config mount placeholder is 0000; its readonly bind supplies
the verified root:`_kea` 0440 source inode, never a world-readable configuration.

The fixed `setpriv` command launches `/usr/sbin/kea-dhcp4` as the existing `_kea`
account, no supplementary groups, only NET_RAW/BIND_SERVICE, no-new-privileges,
and the stock `kea-dhcp4` AppArmor profile. The standalone validation child uses
`kea-lfc`, its stock profile and zero capabilities. No arbitrary path, shell,
hook, control socket or environment override is accepted. All inherited FDs
are sealed before exec. Spawn/Wait retain the same OS thread; setpriv reapplies
SIGKILL parent death after dropping credentials. `SysProcAttr.PidFD` pins the child
atomically at creation, before Wait can reap it; no post-reap PidfdOpen lookup is
used. Missing kernel pidfd support aborts while reap is still blocked. Outer KillMode=control-group
drainage remains necessary, including LFC descendants after role death.

Lease files must be regular, single-link, owner `_kea`, mode 0600 without ACLs,
inside a mode-0700 owned directory. Unknown files, LFC PID files and totals over
the trusted storage budget are rejected. A directory flock serializes cooperating
owners; Root must keep the stock service masked and exclude other `_kea` writers.
This is not an enforced disk quota or protection against compromised Root.

Kea 2.6.3 `-T` appends `persist=false` and cannot validate memfile history. Instead,
each allowed original file is copied into disposable private tmpfs and checked
by the maintained `kea-lfc -4 -d` reader. Serving requires exit zero, exactly one
read/write statistic with zero errors, a termination event and no warning/error
or truncated diagnostic. Copy/original hashes must agree before binding the
original directory. LFC output is discarded, never installed as recovered data.
This validates supported file syntax, not cryptographic provenance, arbitrary
semantic corruption or cross-configuration ownership. The engine's original
lease loader still owns actual startup and lease behavior.

Cancellation sends SIGTERM, then SIGKILL after the existing five-second shutdown
budget, waits and drains descendants. Returning from the component is not enough
to release private mounts: the dedicated role must exit, and Root must verify
whole-cgroup drainage. Errors preserve original files. No readiness or packet
permission is returned by this component.

Serving stdout/stderr are the fixed inherited `*os.File` descriptors directly.
There is no Go passthrough copier, queue or internal serving-log quota: journal
backpressure must not prevent Wait/reap after cancellation. Root must bound the
external unit/journal's rate, retention and storage. LFC diagnostic capture stays
bounded in RAM and never forwards to an external writer. The real-full-pipe
negative cancels and reaps without reading the blocked stdout pipe.

## Native entry for Root's reviewed fixture

Build `go test -c -o server-native.test ./internal/previewruntime`. The test is
`TestNativeRoutedDHCPServerV1`, opt-in `ANDEIVA_DHCP_SERVER_NATIVE_V1=serve` or
`corrupt`. It rejects CI, WSL, non-Debian-13 and host NET/MNT/PID namespaces.
FD3/4/5 are actual retained host NET/MNT/PID pins. The process must be in the
existing fixed grouped cgroup. Root provides private `/run/andeiva-kea-fixture` (0:0:0700) with
`leases` (`_kea` ownership, 0700); config is created once and verified on reuse.
Root supplies a private proc mount and a private mount namespace for every run.

The server LAN is fixed `lan0`, 198.18.1.1/24, one dynamic address 198.18.1.100,
120-second lease, 60/105 timers, subnet ID 17, no DNS/NTP. Use the existing
reviewed dhcpcd client fixture rather than a new DHCP implementation. The native
test writes `prepared.json` only after observing the actual binary, namespace,
UID/GID, capability sets, NNP, AppArmor enforcement and its owned LAN RAW socket.
This is a component observation, not selected-policy readiness. Root keeps
clients isolated until that observation, then checks real BOUND/RENEW, disabled
interface silence, SIGTERM/Wait, and restart with the same lease directory.
Archive the old prepared observation before a new invocation; stale markers are
rejected. Missing explicit SIGTERM causes the 120-second fixture deadline to fail.

For the corrupt mode, Root supplies a copy of the real lease with an invalid
extra row. The test requires Kea's specific row-error diagnostic before serving
and identical original bytes afterward. Keep valid original evidence separately.
No native PASS, lease continuity, AppArmor LFC-transition, runtime performance or
production integration is claimed by local unit tests. Docker/EKS units are
unchanged. Native resource measurements and independent review remain required.

Local checks: `go test -race ./internal/previewruntime -run '^TestRoutedDHCPServer'`,
`go test -race ./internal/dhcpkea`, `go vet ./internal/previewruntime`.
Source semantics: Kea 2.6.3 `json_config_parser.cc`, `lease_file_loader.h`,
`lfc_controller.cc` and `lfc_messages.mes`; Debian 13's
[setpriv](https://manpages.debian.org/trixie/util-linux/setpriv.1.en.html).

Mount a private tmpfs on `/run` before creating this mountpoint. The test retains its fixture directory FD before the component overlays `/run` again.

For the veth fixture, peers are UP only to provide carrier required by Kea. Peer namespaces contain no processes, endpoint addresses or clients before the prepared observation. Start only the reviewed client afterwards. This physical isolation is not a product RAW-traffic gate.

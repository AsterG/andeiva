# Typed network plan qualification

## Group mode awaiting native qualification

`--run-isolated-group-lab-with-flows` reuses these three namespaces and the
reviewed host-anchor mechanism. Source/unit checks pass; native Debian execution
remains pending owner review/authorization. The mode uses the real
routedactivation Engine/Group, exact prepared snapshot, fixed-table nft transport
and an explicitly trusted ephemeral artifact resolver. The resolver is a fixture
record, not a durable production coordinator.

It starts with an actually installed canonical schema-4 policy containing two
saved rules. It proves pending TCP/UDP SNAT and exact cold recovery, then creates a new fixture
operation and confirms a distinct thirty-second lease. Every later policy change
uses Group; existing NAT/conntrack/deny/revocation checks remain. A final changed
policy restores the exact saved schema 4, confirms it and reactivates schema 6.
The final inverse 6→4 expires at its original thirty-second deadline and must
reapply the actual previous schema-6 network/rules. Only a successful complete
table query proves absence. Fixture baseline provisioning does not qualify
production Boot/SystemBundle publication; PrepareColdBoot is tested separately.

The local profile starts no gateway service processes/listeners and checks actual
isolated gateway TCP/UDP socket tables. Host SSH/HTTPS are never enumerated or
stopped. A permanent IPv6 neighbor on the owned LAN peer lets the IPv6 test reach
the forward drop without adding an allow. Forwarding is enabled only after real
owned deny/target rules exist.

Additional markers are emitted only after successful checks:

```text
PASS typed group initial schema4 has exact two saved rules
PASS typed group TCP/UDP SNAT and exact cold recovery
PASS typed group distinct confirmed lease and exact lost-confirm reconciliation
PASS typed group saved schema4 restores exact two-rule legacy and empty network
PASS typed group confirmed schema4 reactivates owned schema6
PASS typed group inverse saved schema4 deadline expired and exact schema6 recovered
```

Group execution is bounded to 80 seconds plus independent bounded cleanup;
the original non-group mode remains 55 seconds. Product lease deadlines do not
change. Source `3918ad8` passed the earlier native group scenario in 46.166222 s
(CPU 13.259767 s, peak 31,281,152 bytes); that evidence does not qualify this new
inverse/two-rule runner. This
mode does not qualify helper restart, existing management LAN migration, endpoint
continuity or durable production recovery. RecoverPrepared has separate unit
coverage and requires authenticated original WorkScope and the same retained
namespace incarnation; NewWithHost is not a reconstruction capability.

```sh
go test -race ./cmd/andeiva-routing-lab ./internal/routedactivation ./internal/nftguardian ./internal/networkexecutor -count=3
```

The existing three-namespace Debian 13 laboratory now applies the gateway's two
static IPv4 addresses and default route through `internal/networkexecutor`.
The runner verifies the namespace it created, opens and checks the mount inode,
then gives the executor a trusted descriptor and an independent supervisor
recovery lifetime. Veth creation, MAC/link state, peer routes and IPv6 setup remain
fixture setup. Existing TCP/UDP, SNAT, deny, revocation, IPv6 and optional observed
conntrack checks remain in place. No additional namespaces are created.

For the root-owned laboratory unit with minimal capabilities, the only opt-in is
the literal `ANDEIVA_LAB_HOST_ANCHOR_FD=0`. The service manager must supply FD 0
from `StandardInput=file:/proc/1/ns/net` before dropping privileges; the runner then
uses `NewWithHost` with `os.Stdin`. Arbitrary descriptor numbers and paths are
rejected. The default still uses `New` and its PID 1 anchor check. This does not
add SYS_PTRACE, accept a caller-supplied namespace identity or relax host checks.
Constructor, apply and verify failures carry distinct English laboratory stages.

Tested unit excerpt for a reviewed root-owned laboratory harness, not a complete
service definition; the supervisor remains in the host network namespace:

```ini
[Service]
StandardInput=file:/proc/1/ns/net
Environment=ANDEIVA_LAB_HOST_ANCHOR_FD=0
```

The flow-observation mode requires `nf_conntrack_netlink` to be loaded before
starting the runner. Check `test -d /sys/module/nf_conntrack_netlink`. If absent,
only the explicitly authorized root supervisor may run
`sudo modprobe nf_conntrack_netlink` as a laboratory prerequisite. The helper does
not load modules and must not receive SYS_MODULE; do not add SYS_PTRACE for PID 1
access. No tools or packages are installed by this runner.

`Apply` and `Verify` must succeed before traffic tests. On exit, child processes
stop first; `Restore` verifies the original controlled IPv4 snapshot, `Close`
releases the pin, and namespace cleanup runs last. Restoration uses the supervisor
lifetime even if the lab request expires. Cleanup errors fail the runner.

Expected markers, emitted only after the corresponding successful operations:

```text
PASS typed network plan applied/readback
PASS typed network plan applied/readback/restored
PASS namespaces cleaned; host routes and nftables unchanged
```

Source `460fece`, binary SHA-256 prefix `590a4005`, passed native Debian 13 amd64
qualification with only SYS_ADMIN/NET_ADMIN and the supplied host FD 0. All typed
plan, TCP/UDP SNAT, real conntrack, related ICMP, IPv6/reverse denial, TCP
revocation, routing without NAT, NAT authorization-boundary and cleanup/outer host
invariant checks passed. Root and architecture reviews found no critical/high/
moderate findings. Elapsed 4.408428 s, CPU 1.116154 s, peak 32,321,536 bytes;
single fixture measurement, not an appliance capacity benchmark.

Before reproduction, run unit checks without privileges:

```sh
go test -race ./internal/networkexecutor ./cmd/andeiva-routing-lab ./internal/routednft
go vet ./internal/networkexecutor ./cmd/andeiva-routing-lab
go build -trimpath -o /tmp/andeiva-routing-lab ./cmd/andeiva-routing-lab
```

Only after source review and explicit isolated-lab authorization, on the disposable
Debian 13 amd64 VM with a recovery snapshot and the required tools already installed:

```sh
sudo /tmp/andeiva-routing-lab --run-isolated-lab-with-flows
```

Never use this command on a customer appliance or change Windows/VPN networking.
The executor requires an empty IPv4 baseline; existing management LAN migration,
DHCP and durable recovery are unsupported. Recovery state remains in memory.
No host routing, NAT, firewall or sysctl is changed. The fixture does not establish
production readiness, mandatory traffic inspection, Docker/EKS integration or the
full Firewall & Routing Alpha milestone. Container execution and appliance
resource budgets remain unqualified.

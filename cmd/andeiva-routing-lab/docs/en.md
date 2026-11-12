# Typed network plan qualification

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

This integration is prepared for review; no privileged qualification is claimed.
First run unit checks without privileges:

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
full Firewall & Routing Alpha milestone. CPU/RAM measurements remain pending.

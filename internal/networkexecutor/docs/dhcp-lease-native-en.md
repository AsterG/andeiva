# Real DHCP to isolated LeaseExecutor fixture

Experimental Debian 13 qualification only. Native results and resource evidence
for this combined fixture are pending. Earlier DHCP and LeaseExecutor tests
qualified those components separately. This adds no appliance API, persistent
configuration format, second database, host adoption or production topology.

Build without privileges:

```sh
go test -race ./internal/networkexecutor -run DHCPLease -count=1
go vet ./internal/networkexecutor
go test -c -o dhcp-lease-native.test ./internal/networkexecutor
go build -o andeiva-dhcp-hook ./cmd/andeiva-dhcp-hook
bash -n scripts/dhcp-lease-native-isolated.sh
sha256sum dhcp-lease-native.test andeiva-dhcp-hook scripts/dhcp-lease-native-isolated.sh
```

The two native tests deliberately skip outside the authorized harness; a local
PASS is not native qualification. Transfer artifacts to a fresh root-owned lab
directory, verify hashes and require root-owned single-link regular files, mode
`0555`. Run each mode in a separate bounded systemd unit from that directory:

```sh
ANDEIVA_DHCP_LEASE_LAB_AUTHORIZED=1 ./dhcp-lease-native-isolated.sh lifecycle
ANDEIVA_DHCP_LEASE_LAB_AUTHORIZED=1 ./dhcp-lease-native-isolated.sh owner-death
ANDEIVA_DHCP_LEASE_LAB_AUTHORIZED=1 ./dhcp-lease-native-isolated.sh manager-death
```

Required unit limits: `KillMode=control-group`, `RuntimeMaxSec=360s`,
`TimeoutStopSec=10s`, `LimitNOFILE=256`. Start the outer unit in the normal host
network/mount/PID namespaces: the harness verifies retained host pins against
original `/proc/1` before entering its own private mounts. Use only an authorized
disposable Debian laboratory with standard `dhcpcd`, BusyBox `udhcpd`, `ip`, `nft`,
`unshare`, `mount`, `setpriv` and Bash. No privileged execution in WSL/CI/customer
appliances. No package installation or host daemon is performed.

Three private network namespaces contain the manager, DHCP server and LAN peer.
LAN starts configured at `198.18.0.1/24`; WAN starts empty. The actual maintained
client runs as a separate root/privsep owner in acquisition-only mode. A distinct
UID/GID 62006 helper has only NET_ADMIN, no_new_privs=1, and the real LeaseExecutor.
The parent starts/waits on a pinned OS thread for parent-death semantics. Anonymous
root-owned mode-0600 pipes have fixed read/write directions, exclusive inherited
endpoints and close-on-exec before engines start. Bootstrap binds the observed
root parent PID/start time, child PID, namespace/boot/run identity and DHCP owner
incarnation. These private bounded canonical frames are test assembly, not a
public JSON input or runtime IPC contract.

During each operation, `Current` queries the real owner through those pipes.
The broker retains the client's exact conservative CLOCK_BOOTTIME deadline;
reading never extends it. Grants use the actual client Epoch and event; sequence
also advances on revocation. Rebind revokes authority and withdraws L3 before
signalling the engine. A previously revoked Epoch cannot restore authorization.
No manual WAN L3 command replaces the executor.

Forwarding remains zero for IPv4/IPv6 and the inet forward chain always drops.
Only local WAN DHCP UDP 68→67 to the fixed server/broadcast and UDP 67→68 from
that server are allowed; all other inet input/output drops. DHCP raw acquisition
uses its separate root/privsep role. No traffic-forwarding qualification is made.

`lifecycle` checks real BOUND, unicast RENEW ACK without extra L3 writes, rebind,
owner/helper restart after withdrawal, server death/expiry withdrawal and cached
lease rejection offline. `owner-death` kills the root client process and requires
withdrawal on channel loss. `manager-death` kills the helper with WAN installed:
the LAN must remain unchanged, the fresh helper must refuse occupied-WAN adoption,
and WAN remains until namespace teardown. That outcome is **not restoration** or
cross-process recovery. A durable authenticated selected-work envelope and an
independent kernel expiry guard remain prerequisites for future forwarding.

Record each mode's executed PASS (no skipped role), hashes, cgroup CPU/peak memory,
host dual-stack links/addresses/routes/rules/nftables/forwarding/mount invariants,
and post-stop absence of descendants/namespaces. Private PID1 exit and the outer
cgroup own final process cleanup; the script does not signal a cached server PID.
Do not equate deleted namespace names with disappearance of all namespace pins.

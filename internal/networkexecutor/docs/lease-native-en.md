# Native isolated LeaseExecutor qualification

This is an opt-in Debian 13 laboratory test, not an activation procedure. It
changes no host interface, IP, route, DNS setting or forwarding policy. Run only
in an authorized disposable laboratory, under a bounded systemd service with
`KillMode=control-group`, `RuntimeMaxSec=120s`, `TimeoutStopSec=10s` and
`LimitNOFILE=256`. Never run privileged network tests in WSL, CI or a customer
appliance. Native execution, independent review and resource measurements are
pending for this new fixture.

Build without privileges:

```sh
go test -c -o lease-native.test ./internal/networkexecutor
bash -n scripts/lease-native-isolated.sh
sha256sum lease-native.test scripts/lease-native-isolated.sh
```

Transfer the binary and script to a new root-owned laboratory directory; verify
their hashes and make both root-owned, single-link regular files, mode `0555`.
The supervisor needs standard Debian `ip`, `nft`, `unshare`, `mount`, `setpriv`,
`cmp` and Bash. No daemon or DHCP server is started. Inside the bounded service,
use that directory as working directory and invoke:

```sh
ANDEIVA_LEASE_LAB_AUTHORIZED=1 ./lease-native-isolated.sh
```

The harness first validates host namespace pins, then creates private mount,
network and PID namespaces. Mount changes occur only after rejecting direct
entry with missing/host-current namespace descriptors. A private `/run` holds
the executable and one peer namespace. Two veth pairs provide LAN/WAN with no
connection to host interfaces. LAN starts at `198.18.0.1/24`; WAN starts empty.
IPv4/IPv6 forwarding remains zero, and three inet base chains drop all traffic.

A UID/GID 62006 process with no capabilities must reject the constructor without
effects. A separate process with all five capability sets containing only
NET_ADMIN and no_new_privs=1 uses the real owned-namespace constructor and real
kernel readback. It exercises initial grant, replay denial, same-tuple renewal,
changed address, revocation, CLOCK_BOOTTIME expiry and explicit withdrawal. A
third process must reject the occupied WAN while the original owner retains its
state. The final-readback negative revokes test authority after the last real
kernel query; the transport returns the real bytes unchanged. Compensation must
restore the exact original LAN/empty-WAN state. Read-only namespace descriptors,
identity, closed forwarding and unchanged firewall are checked.

Lease facts originate in a test-owned callback. This qualifies L3 realization
only, not DHCP protocol exchange, authenticated IPC integration, persistent
ownership, autonomous expiry, forwarding or management reachability. Earlier
DHCP client evidence remains separate. Record source/binary hashes, full test
result, cgroup CPU/peak memory and post-stop absence of descendants/namespaces.
The outer supervisor must compare host links, addresses, routes, rules, nftables
and forwarding before/after, including failure and forced-stop cases. A passing
test alone does not prove host invariants or complete teardown. Do not weaken
comparison or identity checks to make a run pass.

## Bounded native result

Debian 13 qualification of source `9c55cc8` passed the capless constructor refusal
and real-kernel lifecycle; the latter took 5.56 seconds and required an explicitly
passing occupied-WAN child process. Grant, same-tuple renewal, address change,
revocation, expiry-driven Refresh, explicit withdrawal and final-readback
compensation preserved the exact LAN baseline. Host dual-stack routes, rules,
addresses, nftables, forwarding and mount state were unchanged; cleanup passed.
The whole test unit used 0.981592 seconds CPU and peaked at 25,997,312 bytes.
These are fixture observations, not appliance sizing. Lease facts were controlled
by the test; this does not qualify DHCP integration, autonomous expiry, durable
ownership recovery, forwarding or Internet access.
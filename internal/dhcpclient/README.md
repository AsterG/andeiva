# Isolated DHCP acquisition adapter

Experimental and not wired into the appliance. This adapter starts the existing
Debian dhcpcd executable; it does not implement DHCP packets or install addresses,
routes, DNS, firewall rules or administrative listeners. A returned lease is
acquisition evidence, never configuration authority or verified connectivity.

`StartIsolated` requires a root laboratory role in network and mount namespaces
different from trusted retained host descriptors. It also requires three private
tmpfs mountpoints, fixed root-owned executable/configuration paths and an exclusive
owner lock. The network helper's NET_ADMIN-only profile and capless API are unchanged.
The root exception is restricted to this opt-in experiment with dhcpcd privilege
separation; a production identity/capability profile is not qualified.

The fixed hook translates bounded environment fields into one JSON record on the
inherited stdout pipe. It cannot launch scripts, modify resolver files or install
server-supplied routes. Only BOUND/RENEW/REBIND/REBOOT grant evidence; cached TIMEOUT,
STATIC, TEST, unsupported route options and invalid IPv4 tuples do not. RECONFIGURE
revokes the previous evidence without killing the owner; it cannot grant or extend
a lease. `Renew` uses SIGUSR1. `Rebind` uses SIGHUP and requires a new confirmed
grant after RECONFIGURE. SIGALRM releases and exits and is never a renewal control.
Invalid
records and process/channel loss invalidate evidence. The client remains in the
foreground; the launcher thread remains pinned until its child is reaped. Stop
invalidates before termination and the outer service must use KillMode=control-group
to reap every privilege-separated descendant after supervisor death.

The hook supplies no authenticated ACK acquisition timestamp. The expiry bound
therefore uses process-start time for the first ACK and the previous grant hook's
CLOCK_BOOTTIME for later ACKs. This can expire early, but never extends validity by
transport delay. Expired evidence is unavailable even if the EXPIRE hook is lost.
Restart never imports a lease file as live authority. A new confirmed ACK is required.

The native fixture uses an isolated BusyBox DHCP server and an already configured
LAN. It checks acquisition, exclusive ownership, renewal, rebind, restart, server loss,
expiry, offline restart and unchanged IPv4 baseline. Preserving that baseline is
not adoption/rollback of an existing host DHCP manager: ifupdown/dhcpcd ownership
migration, durable mementos, L3 effects, NAT renewal, service policy, management
continuity and production activation remain separate required integrations.

## Validation

Unprivileged Linux/WSL:

```sh
go test -race ./internal/dhcpclient
go vet ./internal/dhcpclient ./cmd/andeiva-dhcp-hook
go build ./cmd/andeiva-dhcp-hook
```

Native only: compile `go test -c ./internal/dhcpclient` and the hook, then run
`scripts/dhcp-native-isolated.sh` from a root-owned fixture containing
`dhcp-native.test` and `andeiva-dhcp-hook`. The explicit
`ANDEIVA_DHCP_LAB_AUTHORIZED=1` opt-in and a reviewed bounded systemd unit with
KillMode=control-group are required. The harness creates only disposable namespaces
and private mounts; never run it privileged in WSL or on a customer appliance.
Native qualification and resource measurement are pending until recorded by the
orchestrator. Docker/EKS activation is outside this laboratory profile.
Run a separate fresh fixture with `ANDEIVA_DHCP_EARLY_SERVER_DEATH=1` to kill and
observe server termination through a pidfd before starting the client. That
negative requires no lease evidence for 35 seconds and unchanged LAN state.

The first native run reached BOUND but failed during the then-mislabelled renewal:
Rebind emitted RECONFIGURE, which the hook rejected. A regression reproduced that
rejection before the fix. The native test now separately checks actual RENEW and
rebind, and reports fixed failure stages without exposing raw engine stderr or
hook environment. Those additional native phases remain unqualified until rerun.

## Engine contract sources

- [Debian dhcpcd 10.1.0 manual](https://manpages.debian.org/trixie/dhcpcd-base/dhcpcd.8.en.html):
  foreground, IPv4-only, no IPv4LL, acquisition without system configuration.
- [Debian hook contract](https://manpages.debian.org/trixie/dhcpcd-base/dhcpcd-run-hooks.8.en.html):
  lifecycle reasons and environment fields.
- [Upstream fixed executable hook invocation](https://github.com/NetworkConfiguration/dhcpcd/blob/v10.1.0/src/script.c)
  and [startup/state path handling](https://github.com/NetworkConfiguration/dhcpcd/blob/v10.1.0/src/dhcpcd.c).
- [BusyBox DHCP server sample](https://github.com/mirror/busybox/blob/master/examples/udhcp/udhcpd.conf).

The upstream dhcpcd source is BSD-2-Clause. This repository integrates the packaged
binary without vendoring or redistributing it; package/SBOM closure remains a release gate.

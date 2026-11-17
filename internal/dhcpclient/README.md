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

Leader exit revokes lease and acquisition evidence as soon as the retained child
is observed exited, before `exec.Wait` drains stderr. A descendant holding that
pipe cannot prolong authority. Late hooks and control requests cannot revive it;
process-group termination and reaping still complete before drainage is reported.
This does not bound shutdown if a stream reader itself is blocked.

The hook supplies no authenticated ACK acquisition timestamp. The expiry bound
therefore uses process-start time for the first ACK and the previous grant hook's
CLOCK_BOOTTIME for later ACKs. This can expire early, but never extends validity by
transport delay. Expired evidence is unavailable even if the EXPIRE hook is lost.
Restart never imports a lease file as live authority. A new confirmed ACK is required.

The native fixture uses an isolated BusyBox DHCP server and an already configured
LAN. After acquisition the test explicitly applies the fixture's exact confirmed
WAN address and verifies readback before checking renewal. It removes that owned
delta after stopping the client and verifies the original IPv4 baseline. The client
still runs with `--noconfigure`; these test-only L3 operations are not a production
lease executor. The fixture checks exclusive ownership, renewal, rebind, restart,
server loss, expiry and offline restart. Restoring this fixture baseline is
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
The Debian 13 fixture passed with dhcpcd 10.1.0 and BusyBox: acquisition,
exclusive ownership, an actual RENEW ACK after explicit fixture WAN addressing,
rebind, restart, expiry without a server, offline restart refusal and restoration
of the nonempty LAN baseline. It took 142.14 s; the complete unit used 0.445799 s
CPU and peaked at 19,038,208 bytes. A separate early-server-death test passed in
35.02 s without lease evidence. These are test measurements, not appliance sizing.
Host nftables, routes and forwarding were unchanged. Acquisition-only renewal
without the fixture's L3 application did not pass and remains a documented boundary.
Docker/EKS activation is outside this laboratory profile.
Run a separate fresh fixture with `ANDEIVA_DHCP_EARLY_SERVER_DEATH=1` to kill and
observe server termination through a pidfd before starting the client. That
negative requires no lease evidence for 35 seconds and unchanged LAN state.

The first native run reached BOUND but failed during the then-mislabelled renewal:
Rebind emitted RECONFIGURE, which the hook rejected. A regression reproduced that
rejection before the fix. The native test now separately checks actual RENEW and
rebind, and reports fixed failure stages without exposing raw engine stderr or
hook environment. Those additional native phases remain unqualified until rerun.
The next native run stayed alive after SIGUSR1 but received no renewal hook in
35 seconds with an unconfigured WAN. The explicit L3 probe above tests the
configuration boundary without increasing that deadline or accepting a silent
no-op as renewal. A passing renewal still requires a new RENEW hook from the engine.

## Internal early-renewal V4 profile

`Scope.EarlyRenewalV4` is trusted supervisor input, disabled by default. It
creates no feature worker, timer or descriptor when disabled. The V4 owner
bootstrap must explicitly enable it; V3 rejects that option. It is not an
administrative API option or an installed-runtime activation.

Using the unchanged conservative BOOTTIME deadline D and current time t, send
once after I=(D-t-14s)/2 only if I≥1s. The 14 s window contains the existing 3 s token
margin, two 5 s response budgets and a 1 s dispatch budget. These are policy limits,
not measured latency. An absolute CLOCK_BOOTTIME timer includes suspension.
There is one pending request. SIGUSR1 never moves lastGrant, epoch or deadline;
only a valid hook may change them. A valid unsolicited hook can satisfy the
request; it is not evidence that the signal caused that ACK.

Late dispatch, short evidence, failed signal/clock and missing valid evidence
within 5 s revoke acquisition evidence. The existing helper must then close and
verify forwarding (B2); the client itself does not modify kernel forwarding.
No synthetic EXPIRE, retry burst or replacement acquisition is introduced.
External observations also reject an overdue response if the worker is delayed.

Integrated acceptance remains pending: the same established TCP connection and
UDP socket must survive at least three renewals. There is a brief interruption
per renewal with forwarding closed. Report each interruption, min/median/max,
packet observations and measured CPU/memory/goroutines with and without B1;
the owner approves the acceptable maximum after seeing the measurements.

### Native component measurements, 2026-11-17

Two fresh, isolated Debian laboratories ran the same 55 s observation loop with
a 60 s server lease. The process measured here owns the client component and
also contains the native test framework; these are not appliance/API totals.

| B1 | Window (ns) | Process CPU (ns) | Maximum sampled RSS (bytes) | Goroutines min/max | Actual renewals |
| --- | ---: | ---: | ---: | ---: | ---: |
| Off | 55000796941 | 436522000 | 9007104 | 6 / 6 | 1 |
| On | 55000182642 | 419576000 | 8978432 | 8 / 9 | 3 |

CPU uses RUSAGE_SELF; RSS samples `/proc/self/statm`; goroutines use the Go
runtime. One paired run does not establish a CPU/RSS improvement. Both units
exited successfully; host addresses, routes, forwarding and namespace list
matched baseline after cleanup. No same-socket traffic survival or interruption
duration was measured by this component test.

Reproduce with the fixed native harness, root-owned artifacts in a disposable
Debian laboratory and a bounded systemd unit with KillMode=control-group:
`scripts/dhcp-native-isolated.sh --early-renewal-off`, then
`scripts/dhcp-native-isolated.sh --early-renewal-on`. Each requires the working
directory to contain `dhcp-native.test` built from this package and
`andeiva-dhcp-hook`; the harness refuses untrusted artifacts and host namespaces.

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

## Alpha interruption measurements — 2026-11-17

The owner provisionally approved a maximum 10s interruption per renewal for this
Alpha milestone test only. Any measured upper bound above 10s fails the test;
this is not a product target. Three two-vCPU Debian interruptions measured
7.897–9.406s,7.813–9.336s and 7.654–9.268s. The same TCP connection delivered 308/308
messages with 15 retransmissions; the same UDP socket sent 1851 datagrams and
received 943 echoes, leaving 908 requests unobserved at the sink after bounded
drain. UDP loss during closure is a limitation. These are application observations,
not an exact wire-packet capture. The complete trial FAILED 141.15s on subsequent
API recovery. It is not full acceptance or permission to enable the profile.

Recommended operational Alpha lease: at least 1h;120s is a stress-laboratory
profile. This recommendation reduces interruption frequency; it cannot change
leases assigned by a provider or authorize rejecting their valid evidence.
The scheduler formula requires a separately reviewed adjustment for measured
adoption time. Its current signal interval and all production bounds remain
unchanged. Atomic handover is required before any version after Alpha; it is
not designed here. API recovery and new-instance recovery remain separate gates.
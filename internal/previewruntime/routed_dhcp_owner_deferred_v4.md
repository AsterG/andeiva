# Deferred DHCP owner v4 — internal integration contract

Isolated implementation awaiting independent review, grouped-runtime wiring,
native acquisition/privsep/cleanup evidence and resource measurements. The v3
immediate-acquisition profile remains distinct and retains its wire contract.
Neither profile is a public administrative endpoint or an operational release.

`PrepareRoutedDHCPDeferredOwnerV4` accepts only a root-selected canonical DHCP
plan and retained namespace capabilities. It creates the fixed root producer,
private bounded mounts and inherited channels, but does not start dhcpcd.
Static WAN and NoNetwork create no producer; unsupported plans are rejected.
Desired.Hash cannot change within an incarnation. A new plan requires explicit
root selection and a new owner/scope; this does not solve dynamic attach for a
NoNetwork-to-DHCP transition in the appliance factory.

`TakeReaderFiles` transfers Current request/reply pipes and one real producer
pidfd, once. There is no acquisition descriptor or placeholder before activation.
The root-authenticated v4 binding fixes LeaseOwner to the producer PID/start,
boot/run/incarnation and canonical Desired. The helper uses
`NewRoutedDHCPDeferredReaderV4`; API receives neither binding nor descriptors.
Root retains its own producer pidfd. v3 and v4 frames/bindings reject each other.
The separate role uses the existing role-local FD3..10 map; helper FD assignment
remains integration work and must not reuse its integrity/retirement descriptors.

Only root calls `Activate`, exactly once, after selected revision, helper
integrityReady, LAN bootstrap/readback and independent EmptyListeners are proven.
These are mandatory supervisor preconditions, not an API boolean. No request on
the helper Current channel can activate, confirm, stop or select a plan.

Activation uses a private two-step exchange. Root sends activate; the producer
starts the existing fixed `dhcpclient.StartIsolated` profile, independently pins
the actual dhcpcd PID/start/parent/net/mount and reports that identity to root.
Root performs its own pidfd/identity verification and retains the actual-child
pidfd, then sends confirm for that exact identity. Only after confirmation may
Current read confirmed DHCP evidence. Preactivation and preconfirmation return
unavailable, with no lease, epoch or R2 authority. Failed activation terminates
the incarnation and cannot retry/reattach. Root activation waits at most ten
seconds; the existing Current transport remains 8 KiB/two seconds including
lock wait.

Event.PID is always checked against actual dhcpcd, never the producer. Current
checks the producer pidfd at the receiver and actual-child liveness before and
after source reads at the producer. A bounded 100 ms producer watch also notices
child death while idle. Death makes the incarnation terminal; it cannot recover
by reusing a numeric PID, changing acquisition start ticks or publishing another
child. Ordinary confirmed lease renewal remains owned by maintained dhcpcd.
RPC sequence differs from lease epoch/fact sequence. Repeated reads of the same
lease produce identical facts and retain the original BOOTTIME deadline.
Expiry, malformed/replayed/cross-profile frames, EOF and cancellation never use
cached grants. Observed unavailability revokes the previous lease epoch.

Root Stop before activation creates no acquisition child. After activation it
stops and reaps the child and adopted descendants before acknowledging. Invalid
control or EOF stops without success acknowledgment. On startup/activation
failure or abnormal producer death, the outer supervisor must still drain the
entire dedicated cgroup before retirement. A leader's death alone is insufficient.

The root/privsep requirements, fixed paths, isolated mounts and filesystem limits
are unchanged from [v3](routed_dhcp_owner_v3.md). No NET_RAW-only capability claim,
new engine, API/helper privilege increase or unit modification is made here.
Standby consumes one producer process and private mounts only while a DHCP plan
is selected. CPU/RAM/latency and native lifecycle measurements remain pending.

Unprivileged Go 1.27.4 checks (`GOTOOLCHAIN=local`):

```sh
go test -race ./internal/previewruntime -run TestRoutedDHCP -count=1 -timeout=2m
go vet ./internal/previewruntime
go build ./internal/previewruntime
GOOS=windows GOARCH=amd64 go test -c ./internal/previewruntime -o /tmp/andeiva-owner-v4-windows.test.exe
```

Tests drive real pipes with acquisition/process-liveness doubles and include v3
regressions. They do not execute privileged mounts, DHCP or a VM. Native evidence,
Docker/EKS support and readiness are not established. Rollback removes this
unwired v4 profile and restores the shared v3 helpers from its parent commit;
no installed configuration or shared state changes.

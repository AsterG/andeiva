# Routed DHCP acquisition owner v3 — integration contract

Status: isolated implementation; grouped-runtime wiring, independent review,
native DHCP/privsep validation and resource measurements remain pending.
This document is an internal developer contract, not an appliance operator guide.

The producer reuses `dhcpclient.StartIsolated` and the maintained fixed dhcpcd
acquisition profile. It does not configure addresses, routes, DNS, listeners,
forwarding or NAT. A live lease is evidence for the existing selected runtime,
not permission to change policy. No new DHCP engine or public endpoint is added.

## Trusted launch ordering

Only the grouped root supervisor may call `StartRoutedDHCPOwnerV3`. This starts
acquisition immediately, so the caller MUST first verify helper integrity
readiness, the exact selected canonical DHCP revision, LAN bootstrap/readback
and independent EmptyListeners. Do not weaken those gates to launch early.
Static WAN must create no acquisition process. The implementation rejects
non-DHCP plans. Wiring these gates is outside this isolated change.

Options contain root-retained gateway/host namespace descriptors and canonical
desired state. They are never API, CLI or helper request authority. Root creates
a separate mount namespace and a fresh random incarnation, then launches only
the current root-trusted executable through fixed `/usr/bin/nsenter` arguments.
The executable must dispatch `RoutedDHCPOwnerRoleV3` to
`RunRoutedDHCPOwnerRoleV3`; there is no arbitrary executable or path option.

This role is root because the existing acquisition profile requires root and
dhcpcd privilege separation. NET_RAW alone is not a supported claim. Review the
root unit's namespace/mount/privsep/capability and syscall constraints before
activation; API remains unprivileged and the existing helper remains NET_ADMIN
only. No deployment profile is changed here.

## Private authority and lifecycle

The separate role uses inherited FDs 3 gateway namespace, 4 host network
namespace, 5 host mount namespace, 6 bootstrap input, 7 lifecycle output,
8 Current input, 9 Current output, 10 root-only Stop input. These numbers do not
change the helper's FD13 integrity or FD14 retirement receipt. The supervisor
must assign new helper descriptors when integrating the reader.

The role verifies root parent PID/start ticks, cgroup, namespace types/inodes,
root-owned private pipes and the selected interface's name/MAC/index before
starting acquisition. Root independently pins both the supervising role and the
actual dhcpcd process with pidfds, parent/start/namespace checks and a second
liveness check. `TakeReaderFiles` transfers exactly one reader capability and
root-authenticated binding; close the parent's copies after inheritance. Never
pass these capabilities or the binding through the API. Binding JSON is bounded
and strict; its contents alone do not authenticate a caller.

The reader serializes bounded Current exchanges (8 KiB frames, two seconds
including lock wait). Every call checks both pidfds before/after obtaining a
fresh source result. No cached grant is returned on malformed JSON, duplicate
fields, sequence/incarnation mismatch, EOF, cancellation, process death or
expiry. RPC sequence is separate from confirmed lease epoch and fact sequence:
polling the same lease returns an identical fact and the original BOOTTIME
deadline. Unavailability revokes the epoch; only a later confirmed epoch can
replace it. Cached TIMEOUT grants are rejected. No wall-clock expiry conversion
or automatic deadline extension is used.

Only the root control pipe accepts Stop. Current cannot renew, rebind, stop,
execute commands or provide paths. dhcpcd owns its normal renew/rebind lifecycle.
Stopping cancels acquisition, waits for its direct child, then kills and reaps
adopted descendants before acknowledging. Malformed control or pipe EOF stops
without a success acknowledgment. If the role dies abruptly or startup fails,
the supervisor MUST drain the entire dedicated cgroup with the existing gate
before scope retirement. A pidfd or successful leader exit alone is insufficient.

## Scope and resource boundaries

All mount changes occur only after checking the fresh private mount namespace.
The role makes propagation private and overlays fixed `/run` and `/var/lib`
tmpfs mounts (4 MiB each), plus three fixed acquisition directories (1 MiB each),
each with 128 inode limits and nosuid/nodev/noexec. These are upper filesystem
capacity bounds, not measured RSS. Child output is discarded; private protocol
errors use stable generic codes. There are no public sockets or collector timers.
Actual CPU/RAM, dhcpcd privsep paths and cleanup behavior require native evidence.

## Reproducible unprivileged checks

With Go 1.27.4 and `GOTOOLCHAIN=local`:

```sh
go test -race ./internal/previewruntime -run TestRoutedDHCPOwnerV3 -count=1 -timeout=2m
go test -race ./internal/previewruntime ./internal/dhcpclient -count=1 -timeout=3m
go vet ./internal/previewruntime ./internal/dhcpclient
go build ./internal/previewruntime ./internal/dhcpclient
GOOS=windows GOARCH=amd64 go test -c ./internal/previewruntime -o /tmp/andeiva-owner-windows.test.exe
```

Tests use private pipes, fabricated lease evidence and an ordinary unprivileged
process for pidfd lifetime checks. They do not run DHCP, mount filesystems or
change host networking. Linux launch/role paths are not qualified by these tests;
other platforms reject launch and reader construction. Container/EKS support,
native grouped restart, real ACK/renew/rebind/expiry and cgroup death drainage
are not established. Rollback is removal of these unreferenced new files;
no installed runtime configuration or shared state is changed.

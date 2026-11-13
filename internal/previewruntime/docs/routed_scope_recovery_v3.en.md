# Root scope retention and normal retirement

The experimental managed service now publishes a root operational manifest and
seven named descriptors before creating or enabling L2 links. Installation must
call `PrepareRoutedScopeRecoverySlotV3` to reserve the fixed root-owned 0600,
4096-byte `grouped-scope-v3` file. Runtime never creates, enlarges or overwrites
an unfinished slot. This is operational evidence, not a second configuration
store; selected G1/R2 authority remains mandatory.

The descriptors retain the manifest, gateway network namespace, mount namespace,
original pre-bind file, root namespace directory, original cgroup and its
`cgroup.events` file. The events descriptor is captured with `openat` on that
cgroup before effects; every identity is recorded. Root persists/fsyncs the
manifest, sends each FD with `FDPOLL=0`, waits for a separate notification barrier,
and reads the actual manager store. All seven names, device/inode identities,
modes and access flags must match. A barrier alone is never acceptance. Partial
publication retains evidence and blocks effects; it does not retry or discard
unknown entries.

The service uses `NotifyAccess=main`, `FileDescriptorStoreMax=7` and
`FileDescriptorStorePreserve=yes`. Root MAIN consumes `LISTEN_FDNAMES` before
opening other descriptors: exactly the management listener, or that listener
plus all seven anchors, in any order. Duplicates, partial sets, foreign names and
aliases fail closed. Accepted FDs are duplicated CLOEXEC; the management listener
still undergoes namespace, interface and address validation by the supervisor.

Normal close requires child drainage and successful explicit link/namespace
teardown, then exact manager removal, a barrier and verified empty readback.
Local retained copies close before the existing retirement receipt is written.
Only an exact matching completed receipt and empty manager store permit clearing
the manifest. No step treats pathname absence or FD release as synchronous RCU
namespace destruction. Failure leaves evidence and prevents a false receipt.

**Crash recovery is still blocked.** Inherited recovery anchors are validated but
rejected before new creation. No `ENODEV`, missing path, replacement cgroup or
manifest alone authorizes orphan cleanup. The separately observed native old
cgroup events behavior has not been promoted to cleanup authority. Retained FDs
provide no OS-reboot, suspend or power-loss guarantee.

Focused tests use explicit manager doubles and real Unix descriptor transfers
for barriers; they do not qualify native systemd storage or privileged teardown.
Native store/normal-close/partial-failure/SIGKILL qualification and resource
measurements remain pending. No host or appliance was activated.

```sh
go test -race ./internal/previewruntime -run TestRoutedScopeRecoveryV3 -count=3
go vet ./internal/previewruntime
go build ./internal/previewruntime
bash packaging/preview/tests/api-lifetime-unit-graph.sh
```

[systemd257 service FD store](https://www.freedesktop.org/software/systemd/man/257/systemd.service.html),
[named inheritance](https://www.freedesktop.org/software/systemd/man/257/sd_listen_fds.html),
[notification barriers and FDPOLL](https://www.freedesktop.org/software/systemd/man/257/sd_notify.html),
[manager readback](https://github.com/systemd/systemd/blob/v257/src/analyze/analyze-fdstore.c).

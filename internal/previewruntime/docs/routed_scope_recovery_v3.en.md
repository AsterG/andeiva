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

## Native store qualification (opt-in, not yet executed)

`TestRoutedScopeRecoveryV3NativeStore` must run directly as MainPID of a transient
`andeiva-preview-grouped.service` on an isolated Debian 13 client where the
service and its socket are both absent. Root must verify `LoadState=not-found`
for both before launching; never replace an installed unit. The test checks
root/non-CI, MainPID, transient unit properties, exact cgroup and a mount namespace
different from PID1 before effects. It creates only an empty gateway namespace,
a small private directory and a preallocated manifest: no L2, listeners, lease
grant or retirement receipt. Seven real anchors traverse Store/barrier/readback,
independent VerifyStored, Drop/barrier/empty readback and local Close.

The test timeout is 30s; the unit limit is 45s and each manager call is bounded.
Root retains the unique fixture path and unit InvocationID. A partial Store/Drop
failure keeps its evidence and manager anchors; inspect them before any cleanup.
A SKIP or expected nonroot refusal is not native success. After success Root
must independently verify empty FD store, unit cleanup, unchanged host network
and mount state, and collect CPU/memory. No orphan recovery is qualified here.

```sh
# Root preflight must show not-found for both units.
systemctl show -p LoadState andeiva-preview-grouped.service
systemctl show -p LoadState andeiva-preview-grouped.socket
# Substitute the independently verified, root-owned test artifact path.
systemd-run --unit=andeiva-preview-grouped.service --wait --pipe \
  --property=Type=exec --property=NotifyAccess=main \
  --property=FileDescriptorStoreMax=7 --property=FileDescriptorStorePreserve=yes \
  --property=PrivateMounts=yes --property=PrivateTmp=yes \
  --property=KillMode=control-group --property=NoNewPrivileges=yes \
  --property=RuntimeMaxSec=45s --property=TimeoutStopSec=3s \
  --property=TasksMax=64 --property=LimitNOFILE=256 --property=MemoryMax=256M \
  --setenv=ANDEIVA_SCOPE_STORE_NATIVE=1 \
  /ROOT_OWNED_FIXTURE/routed-scope-store-native.test \
  -test.run=^TestRoutedScopeRecoveryV3NativeStore$ -test.v -test.timeout=30s
```

Creation-time capture now also verifies the system manager reports this Root process as MainPID, the fixed cgroup and Delegate=no. The manifest records its InvocationID; delegated or group/other-writable cgroup controls are refused. The old events parser distinguishes live populated state from ENODEV on the exact original FD, but neither observation is wired to teardown authority. Crash retirement still requires an authenticated full G1/R2 reader and the existing writer publication lock; no current selected proof is manufactured from the manifest.

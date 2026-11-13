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

The experimental same-boot consumer now binds inherited anchors to exact CURRENT
selected work through the private capless preflight reader. Root holds the
existing `checkpoint.lock` throughout. Full G1/R2 chooses DHCP, Boot, Pending or
Active work; historical matches, corruption, unsupported ordinary intents and
missing selected scope are refused. No initial scope is fabricated before L2.

The live-cgroup path requires a nondelegated invocation, no children and either
zero members in a distinct old group or Root alone in a reused group. The new
deactivation path requires ENODEV with zero bytes on the authenticated original
events FD, distinct old/current cgroup inodes on the same device, and distinct
actual invocations. Exact selected work under the original lock, all seven
anchors, current BootID/host namespace, current nondelegated unit and Root-only
drainage are revalidated before success. ENOENT, partial reads, changed identity
or any failed proof still refuse. Independent review and native retirement
qualification are pending; the prior native attempt stopped at the former
ENODEV rejection with seven FDs retained. No OS-reboot, suspend or power-loss
recovery is added here.

After selected proof and drainage, fixed commands close IPv4/IPv6 forwarding,
verify it, and remove only recognized private MACVLAN children in the retained
nonhost namespace. The selected tuple is rechecked before detach and before
releasing the store. A dedicated locked thread enters the retained private mount
namespace, verifies the exact gateway pin, detaches it, checks the original
underlay and unlinks that file; its filesystem context never returns to Go's
thread pool. Runtime cleanup accepts only exact metadata, the anchored netns
directory, empty api directory and the two typed IPC socket names. Root uses its
existing CAP_CHOWN only on the proven IPC directory after drainage. Unknown or
changed entries block cleanup; no recursive delete or additional capability is
introduced. Store removal, local-pin closure and another lock check precede the
retirement receipt. That receipt does not claim address rollback or lease renewal.

A partial detach/chown/removal can leave a state requiring operator inspection;
unknown ownership and absent anchors are not silently treated as idempotent
success. Same-boot crash retirement is not yet natively qualified.

Focused tests use explicit manager doubles and real Unix descriptor transfers
for barriers; they do not qualify native systemd storage or privileged teardown.
Native normal-close/partial-failure/SIGKILL qualification and resource
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

## Native store qualification (opt-in)

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

Creation-time capture now also verifies the system manager reports this Root process as MainPID, the fixed cgroup and Delegate=no. The manifest records its InvocationID; delegated or group/other-writable cgroup controls are refused.

The preceding seven-anchor Store/Drop fixture passed on Debian 13 in 0.11s, with
external host invariants unchanged. CPU/RAM figures were unavailable. This
qualifies neither the new crash-retirement consumer nor its partial-failure paths.

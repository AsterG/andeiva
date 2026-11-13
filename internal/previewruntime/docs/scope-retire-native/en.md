# Retained-scope retirement component qualification

Status: fixture implemented; native execution and resource measurements pending.
An unprivileged test skip is not native qualification.

The opt-in fixture runs as the MainPID of two successive invocations of the
fixed transient `andeiva-preview-grouped.service`. Use only an authorized Debian
13 laboratory where that service and its socket are absent. Root executes the
fixture; do not run it in CI, privileged WSL, or an installed appliance.

The first invocation persists seven real anchors before L2 or Boot effects,
then starts the existing API/helper roles against real G1/R2 storage and an
isolated gateway. The API has no capabilities; the helper has only NET_ADMIN.
MACVLAN children have veth parents in two additional isolated namespaces. No
address, route, forwarding permission or host firewall rule is added. After
real Boot/readback and child Wait, Root kills only itself with SIGKILL.

The second invocation accepts exactly seven named descriptors, rejects a held
publication lock, and calls the production retirement core. It checks selected
history through the real capless reader, current invocation/cgroup drainage,
network closure, namespace teardown, FD-store removal and the exact receipt.
ENODEV remains a rejected branch: observing it produces a failure with retained
evidence, not PASS. Unknown state is never treated as a completed retirement.

This is a **core component** test. It supplies actual reader roots directly and
does not qualify the deployment loader, migration provenance, managed restart,
OS reboot or the eight-descriptor management handoff. The schema-1 bootstrap
uses real source/sink namespaces; its schema-2 operational projection preserves
BootID, RunID, host and gateway exactly. The selected owner identity is unchanged.
The parent namespaces model external links and are outside the gateway receipt.
Their pins exist only in the old private mount namespace retained by the store.

Build and unprivileged checks:

```sh
go test -race ./internal/previewruntime -run '^TestRoutedScopeRetireV3Native' -count=1 -v
go vet ./internal/previewruntime
go test -c ./internal/previewruntime -o /absolute/output/scope-retire.test
bash -n packaging/preview/tests/scope-retire-native.sh
```

Build from an integration tree containing the fixed selected-preflight TestMain
dispatch. The fixed `systemctl show` queries use `SYSTEMD_OFFLINE=0` for explicit
online operation inside RootDirectory; this follows the
[systemd 257 verb dispatcher](https://github.com/systemd/systemd/blob/v257/src/shared/verbs.c).
No loader validation or LocalOrigin contract is weakened.
The test checks RootDirectory, PrivateMounts, MainPID and InvocationID through
the real manager; it does not read PID1 root/namespace symlinks or add SYS_PTRACE.
The external driver rejects root-path aliases using canonical-path equality.

Root-only command, after independent source/artifact and host-invariant checks:

```sh
bash packaging/preview/tests/scope-retire-native.sh --isolated-lab /root-owned-0755-directory/scope-retire.test
```

The driver creates a private RootDirectory beneath `/var/backups`, with private
passwd/group files and read-only host tool/API mounts. It never installs users
or services. The fixture capability budget includes SYS_ADMIN for namespace
creation and is not the appliance helper budget. Limits: two invocations,
90-second test timeout each, 256 FDs, 128 tasks and 384 MiB memory.

Failure retains the unit's FD store, manifest, receipt slot and fixture files;
there is no automatic stop or recursive cleanup. Success requires the correlated
second invocation, an empty FD store and no MainPID before stopping that exact
unit. PASS comes only from that invocation's journal with successful process
exit/status, never the unit's older log history. Keep the journal, unit properties,
artifact hashes and receipt. Root must
compare host dual-stack addresses/routes/rules, nftables, forwarding, namespaces
and PID1 mountinfo before/after, and record CPU/memory from the actual run.

[Español](es.md) · [Português](pt.md)

# Retained-scope retirement component qualification

Status: fixture implemented; native retirement qualification and measurements pending.
An unprivileged test skip is not native qualification.
The first native attempt failed before Store or network effects: the private
`/run/andeiva-preview/grouped` directory was hidden by RootDirectory's API
filesystem setup. A second attempt bound only that child using a source inside
the hidden subtree; systemd failed with NAMESPACE/226 before executing Go. Both
attempts retained an empty FD store and did not qualify retirement. The driver
now binds the complete fixture-owned `/run` nonrecursively at `/run`. The explicit
mount overrides MountAPIVFS's fallback at the same destination, as implemented
by [systemd 257 namespace setup](https://github.com/systemd/systemd/blob/v257/src/core/namespace.c).
Native verification of this correction remains pending.

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
The third native attempt reached Store and real Boot, then stopped at the former
ENODEV rejection; seven descriptors remain retained. The new core accepts that
observation only with repeated selected-state, anchor, boot/namespace, exact
current unit and drainage proof. Review and native verification remain pending.
Unknown state is never treated as a completed retirement. Attempt markers now
include the actual InvocationID and never overwrite previous failures. Root can
retry the retained unit with a reviewed binary and a new real invocation; this
does not qualify the fresh-unit driver's restart counter or management handoff.

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
or services. Its writable `/run` bind source is strictly beneath the temporary
fixture root, with canonical-path and owner/mode checks; it is never the host's
`/run`. Manager sockets remain separate read-only binds. Persistent
data remains beneath that same private root's `/var/lib`; no host RuntimeDirectory
is created. The fixture capability budget includes SYS_ADMIN for namespace
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

While recovery requires retained descriptors, do not use `reset-failed`, stop,
or recreate the failed transient unit. An observed `reset-failed` caused manager
garbage collection and lost all seven stored descriptors. A remaining manifest
does not authorize adoption or a retirement receipt. Preserve the original
invocation evidence; a direct retry after the start limit expires still requires
verification of the retained descriptors and a new real manager invocation.
It is not qualified by this driver's fresh-unit success checks.

Root recovery errors identify fixed operation stages and retain the underlying
error. The retained-scope run of diagnostic source `b0eeaec` failed specifically
at `detach namespace: enter retained mount namespace` with `EPERM`, retained
seven manager descriptors and the original capture, and produced no receipt.
The fixture now adds only `CAP_SYS_CHROOT`: mount-namespace entry requires it
together with `CAP_SYS_ADMIN` ([setns(2)](https://manpages.debian.org/trixie/manpages-dev/setns.2.en.html)).
An effective/permitted capability preflight and missing-capability unit negatives
run before effects. These unit checks do not replace that native failure evidence
or qualify successful retirement with the amended budget. No helper gains capabilities.

[Español](es.md) · [Português](pt.md)

## Observed component result

An authorized Debian 13 amd64 run completed the two-invocation fixture: the first root process stored seven anchors and was interrupted; the replacement verified the selected configuration under the original lock, drained processes, retired the gateway, verified an empty FD store and published the exact receipt. The harness required one automatic restart and stopped only after success. Host address, route, rule, forwarding, namespace and mount comparisons matched.

The recovery test took 0.67 s; its invocation reported 0.541928 s cumulative CPU and 12,828,672 bytes peak cgroup memory. These measure this fixture, not steady appliance operation. A preceding missing-capability run failed at entry into the retained mount namespace, preserved the seven anchors and produced no receipt. CAP_SYS_CHROOT is required with CAP_SYS_ADMIN for that entry and restoration; API/helper budgets remain unchanged.

Deployment-loader provenance, eight-descriptor management activation, managed reboot and interruption of every teardown step remain separate gates. This result does not close appliance recovery or the Firewall & Routing milestone.
# DHCP jobs native laboratory, v4

This fixture is prepared for an isolated Debian 13 laboratory. Compilation or a
skipped opt-in test is not native qualification. Do not run it in WSL, CI, a
customer appliance or alongside the installed grouped service.

Build the current reviewed sources with Go 1.27.4:

```sh
go test -c -o /tmp/previewruntime-dhcp.test ./internal/previewruntime
go build -o /tmp/andeiva-dhcp-hook ./cmd/andeiva-dhcp-hook
bash -n packaging/preview/tests/dhcp-jobs-native.sh
```

The orchestrator stages these binaries and the script in a root-owned 0755
laboratory directory, with no symlinks, multiple hard links or group/other write
permissions. Record their SHA-256 hashes. Dependencies are `/usr/sbin/dhcpcd`,
`/usr/bin/busybox` with the `udhcpd` applet, iproute2, nftables, nsenter, setpriv
and mount. `udhcpd` is a test packet peer, not the product DHCP server.

The runner must reserve the otherwise absent unit
`andeiva-preview-grouped.service`: the production owner requires that exact
root-owned cgroup, with no delegated children or subtree controllers. An
arbitrary native-test unit cannot substitute for it. The runner supplies a
private mount namespace and a bounded service lifetime with whole-cgroup cleanup;
it must not overwrite or start an installed service. Required mountpoint
directories `/run/netns` and `/usr/libexec` must already exist. Inside that isolated
unit, run the staged script with exactly:

```sh
bash /opt/andeiva-lab/dhcp-jobs-native.sh --isolated-lab \
  /opt/andeiva-lab/previewruntime-dhcp.test /opt/andeiva-lab/andeiva-dhcp-hook
```

The script rejects WSL, CI, the wrong cgroup and the host mount namespace before
effects. It installs the hook only over a private tmpfs, creates three disposable
network namespaces and two isolated veth pairs, and passes namespace pins in
FDs 3–5. No environment variable supplies a process identity. The test seeds the
real offline store, uses Schema1 laboratory metadata and enables the real root
job broker and deferred owner. The helper uses the production selector, shared
LAN executor and real EmptyListeners; the API remains capless and cannot inherit
the helper's private FD15 endpoint.

The first mode tests authenticated Service admission/execution from NoNetwork to
DHCP, complete post-selection inspection, real acquisition, selected `dhcp_live`
verification, independent kernel address/default-route readback, natural renewal
with a later epoch/original deadline, and API-only restart retaining the same
helper and producer incarnation. A rollback while selected DHCP work remains
active must be refused without replacing Running or its lease. Reports are
`ANDEIVA_NATIVE_DHCP_JOBS` JSON with phases `bound`, `renewed`, `restarted` and
`rollback-fenced`; cleanup success is `ANDEIVA_NATIVE_DHCP_JOBS_CLEANUP_OK`.

This mode does not prove transactional DHCP retirement/rollback to NoNetwork,
zero exclusive resources when disabled, lease expiry, owner death, traffic
forwarding, reboot recovery or resource budgets. The closed residual gate is
removed only when the entire disposable namespace is retired. Those remain
separate acceptance gates. Preserve failed evidence and inspect the owning
cgroup before deleting any pin; cleanup rejects a changed namespace or live
namespace process. Never treat missing output as success.

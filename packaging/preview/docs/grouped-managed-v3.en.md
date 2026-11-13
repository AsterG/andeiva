# Managed gateway assembly

The native launcher owns a fresh gateway namespace and two private child links.
Physical parent bindings include index, name, hardware address and MTU. A separate
node-local identity keeps child MAC addresses stable across supervisor RunIDs;
it is not a credential or shared policy. Existing namespaces are never adopted.

Only positively identified child links may be raised or removed. The launcher
sets no address, route, NAT or forwarding policy. IPv6 and forwarding are closed
before link creation. The transaction engine remains responsible for L3 effects
and effective-state verification. API processes remain in the management namespace.

A root cutover record binds the operational deployment and node-link manifests.
This record is not a G1 proof: selected configuration and independent helper
readback must still pass. The namespace is removed only after the inherited
supervisor drains its children. Unknown runtime files prevent cleanup/restart
instead of being deleted. Package installation does not create an activation
record or enable the incomplete grouped service.

Automated tests cover bindings, manifest hashes, link replacement, cancellation,
lost acknowledgements and idempotent cleanup. Installed lifecycle, cold cutover,
DHCP bootstrap and client Internet acceptance are separate qualification gates.

The optional root preparation command `andeiva-preview grouped-retirement-slot` preallocates a fixed 4096-byte retirement slot. The grouped unit can write that file only. Normal shutdown must first observe the dedicated, non-delegated service cgroup with only the supervisor PID, then release the exact owned namespace, before issuing the receipt. Descendants, timeout, unknown files or uncertain cleanup prevent the receipt and retain recovery evidence. This is not a SIGKILL or power-loss recovery guarantee. Fixed-slot filesystem tests and installed process-drain tests are separate gates; the receipt consumer must not be activated before both pass.

### Dedicated process-drain qualification

Build the `internal/previewruntime` test binary on the development machine and transfer it with a verified SHA-256 checksum to a root-owned directory on disposable Debian13. Do not use an appliance where `andeiva-preview-grouped.service` already exists. The fixture runs a fixed helper and an orphan child inside a private-network transient unit. It requires the same dedicated cgroup path and UMask0077 as the proposed service. It checks that a live child after helper Wait prevents both the cleanup callback and receipt for five seconds, then checks pidfd identity/cgroup membership before terminating that child. Only observed drainage permits the test callback and receipt. The callback is a witness; this is not an integrated namespace cutover test.

From the authorized local root console, in the verified binary directory:
```bash
test "$(systemctl show andeiva-preview-grouped.service -p LoadState --value)" = not-found
systemd-run --unit=andeiva-preview-grouped --no-block --service-type=oneshot \
  --property=RemainAfterExit=yes --property=UMask=0077 \
  --property=NoNewPrivileges=yes --property=PrivateNetwork=yes \
  --property=PrivateTmp=yes --property=KillMode=control-group \
  --setenv=ANDEIVA_ROUTED_CGROUP_NATIVE=1 \
  "$PWD/routed-cgroup-native.test" \
  -test.run '^TestRoutedCgroupDrainV3Native$' -test.v -test.timeout=20s
systemctl show andeiva-preview-grouped.service -p Result -p ExecMainStatus -p InvocationID
journalctl -u andeiva-preview-grouped.service --no-pager
# After the unit has completed and the result/logs have been retained:
systemctl stop andeiva-preview-grouped.service
```

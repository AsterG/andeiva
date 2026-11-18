# Durable DHCP subnet IDs

This internal operational registry is separate from configuration history and
leases. It is not wired to the runtime yet. Trusted bootstrap supplies the
protected directory FD and its fixed `leases` child FD; no API chooses paths.
The intended root is `/var/lib/andeiva-preview-package/dhcp-server` (root:root,
0700); `scope-bindings.v1.json` is root:root 0600. The lease directory is 0700;
bootstrap remains responsible for checking the maintained engine's lease owner.

Keys contain the scope ID, selected LAN interface ID, hardware MAC and canonical
IPv4 subnet. Pool and option changes retain the ID. Interface/MAC/subnet changes
allocate another nonzero uint32 ID. Allocation is monotonic; removed mappings
remain, including across disable/re-enable and configuration rollback. Batch
order cannot change allocation order. Limits are 4096 mappings and 1 MiB.
Kea's reserved ID 4294967295 is rejected.

An independent directory flock serializes callers. Publication syncs the
`scope-bindings.v1.pending` marker and directory before staging the new state in
`scope-bindings.v1.publish`. Both files are created exclusively without
following links. The candidate is synced and atomically renamed. The directory
sync for that rename must succeed before the marker can be removed. A leftover
marker or staged file blocks every request. If syncing marker removal fails,
the attempt returns an error without IDs. The manifest was already synced, and
a marker that reappears after restart still blocks requests. The registry leaves
any running service active. Disk I/O can delay cancellation.

The first ID requires an empty, locked lease directory, including when the
manifest already exists with zero entries. At quota, existing keys remain
readable without writes and new allocations fail.

For protected recovery, quiesce the engine and all writers during authorized
maintenance. Preserve the registry files and lease directory together as incident
evidence. Verify storage health, the complete mapping history and its agreement
with retained leases. Sync the verified manifest and its directory before
clearing the marker or staged file, then sync the directory again. If the
mapping cannot be proven, leave the fence in place. Keep all leases.
Configuration rollback must never restore the manifest independently of its
lease history. Detecting arbitrary rollback by root requires an external
monotonic anchor.

Linux/WSL, Go 1.27.4:

```sh
go test -race ./internal/previewruntime -run '^TestDHCPSubnetRegistryV1' -count=1
go vet ./internal/previewruntime
go build ./internal/previewruntime
go test -c -o /tmp/andeiva-dhcp-subnet-registry.test ./internal/previewruntime
```

The root-only filesystem fixture is opt-in with
`ANDEIVA_NATIVE_DHCP_SUBNET_REGISTRY=1` and test filter
`^TestDHCPSubnetRegistryV1RootLifecycleNative$`. It creates and removes only its
temporary directory. It does not start DHCP, change network settings or qualify
service lifecycle, leases, power-loss recovery or production resource usage.
Those integration/native gates remain pending. Source rollback must retain the
registry and leases; no downgrade/reuse migration is provided.

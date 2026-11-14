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

An independent directory flock serializes callers. A new file is written with
exclusive/no-follow creation, synced, atomically renamed and the directory
synced before IDs are returned. Any failed persistence returns no IDs: callers
must not start an engine. A pending file is an uncertainty fence; it is neither
adopted nor automatically deleted. Cancellation is cooperative, not a hard disk
I/O bound. The registry never stops an existing service.

Missing mappings with any existing lease entry refuse initialization. An empty,
locked lease directory permits initialization. At the mapping/byte quota,
existing keys remain readable without writes, while new allocation fails.
Uncertain partial writes instead block resolution until protected recovery;
there is no automatic history repair. Arbitrary root restoration/deletion of
old files cannot be detected without an external monotonic anchor. Configuration
rollback must never restore this registry independently of its lease history.

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

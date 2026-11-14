# Prepared DHCP LAN configuration

Routed policy version 2 adds a required `dhcp_server` object using the existing DHCPv4 server schema 1. Policy version 1 requires that field to be absent and retains its canonical bytes and hashes. The outer configuration remains schema 6, the composite schema 7, and the network schema 1. There is one configuration store and one coordinator; DHCP configuration belongs to the existing routed/firewall revision.

Canonicalization copies all nested data. Scopes, pools, exclusions and reservations are ordered deterministically; DNS and NTP order is preserved. Bindings come from static LAN addresses in the selected network, not caller-supplied runtime inventory. This proves desired consistency, not physical ownership, interface availability or a running DHCP server. Disabled configuration remains validated and retained.

The sticky feature `configuration.routed-dhcp-server.v1` accompanies the first selected operation containing this policy. Candidate/configuration publication independently ensures the feature is present. Removing the DHCP candidate does not clear it. Older readers must reject this store before reconciliation; rollback cannot remove the feature to make an older binary accept it. Legacy stores without the feature are not migrated implicitly.

A trusted routed authority must implement `RoutedDHCPServerSupportV1` and explicitly report support. Existing authorities do not opt in. Without support, admission is rejected before reserve maintenance, claims or operation publication; opening a marked store is rejected before coordinator recovery and engine effects. The capability is not a physical proof. An implementation may report support only when activation, effective readback, compensation and complete shutdown include the server. A successful firewall readback alone is insufficient.

Stage, confirmed Commit, Save and rollback use the existing joint transaction. Configuration rollback must not roll back or discard issued lease ownership. No lease database, Kea launcher, service unit, administrative endpoint, UI, runtime activation or deployment is added here. A future adapter must prove lease persistence, storage-pressure handling, actual serving, disable-to-zero and recovery before enablement.

Existing bounds remain: DHCP input is at most 64 KiB, while the current configuration operation envelope is at most 8 KiB. A valid standalone DHCP configuration may therefore be too large for this prepared transport. It is rejected without truncation; no quota or request limit is increased. The feature's serialized size is reserved in the existing metadata forecast. Runtime resource measurements remain pending.

Run with the project's Go toolchain:

```sh
go test -race ./internal/dhcpserver ./internal/routedmodel ./internal/configpoc -run 'TestCanonical|TestDHCPServer|TestReserveEnvelope'
go vet ./internal/dhcpserver ./internal/routedmodel ./internal/configpoc
go build ./...
go test ./internal/dhcpserver -run '^$' -bench '^BenchmarkCanonical$' -benchmem
```

`TestDHCPServerOldReaderBarrier` additionally requires `-reclaim-old-reader=/absolute/path/to/prior-configpoc.test`, built from the preceding source with its existing `TestReclaimPriorReader` adapter. Without that explicit binary, the compatibility case skips; that is not a compatibility pass. Unit tests use real temporary stores and simulated component engines, not a native DHCP service.

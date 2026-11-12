# Routed network configuration model

This internal package validates desired routed IPv4 configuration. It does not
change interfaces, routes, DNS, forwarding, listeners or nftables. It is not
connected to the administrative API, CLI, Web or transaction coordinator yet.

Schema 1 describes WAN DHCP/static, LAN/management static addresses, compatible
zones, one WAN default route and explicit DNS selection. IPv6 forwarding must be
`deny`; this is a desired enforcement requirement, not evidence of applied rules.
Bridge, VLAN, PPPoE, NAT and DHCP server engines are absent.

`Decode` rejects documents over 64 KiB, duplicate/unknown/aliased control fields,
trailing values and invalid configurations. `Canonical` preserves interface host
bits and produces a deterministic SHA-256 revision from independent collections.
Collection and field bounds also apply to direct Go callers. A hash is integrity
metadata, not authentication or authorization.

Bindings persist interface name and MAC. `Bind` resolves a fresh kernel index
from the trusted read-only inventory, never from an administrative request body.
Indexes may change across boots. Observed addresses are not DHCP lease evidence;
DHCP remains explicitly unresolved until an executor obtains a verified lease.
Binding and inventory hashes are observations, not an atomic kernel snapshot or
proof of reachability, a free address, permissions or management recovery.

Future execution must use an authenticated narrow helper, fresh pre/post checks,
RBAC, audit and the existing transaction engine. Preserve the old administrative
endpoint until independent confirmation/recovery is verified. No adapter may
interpret this validator's success as permission to mutate the host.

Validation:

```sh
go test -race ./internal/networkplan ./internal/jsoncheck ./internal/nftengine
go vet ./internal/networkplan ./internal/jsoncheck ./internal/nftengine
```

Tests cover deterministic revisions, host bits, overlaps, incompatible roles,
invalid gateways/DNS, identity changes, legitimate reindexing, DHCP ambiguity,
strict JSON and input bounds. They do not prove routing, NAT or connectivity.
Rollback of this inactive preparation is code removal; there are no runtime
resources or configurations to clean up. Debian integration and runtime resource
qualification remain pending. See [Spanish](docs/es.md) and [Portuguese](docs/pt.md).

Address validation is not a complete bogon/routing policy. Reserved 0/8 and 240/4
require explicit policy review before any executor is enabled.

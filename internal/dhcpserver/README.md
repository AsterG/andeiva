# DHCPv4 server configuration

Status: bounded configuration contract and validation only. No DHCP server,
listener, lease database, administrative endpoint or runtime integration is
implemented by this package. The WAN DHCP client is a separate component.

Schema 1 declares service enablement and up to 32 scopes. Each scope references
one trusted LAN interface, its selected IPv4 subnet and appliance address, up to
32 nonoverlapping dynamic pools, 256 excluded addresses and 256 MAC reservations.
An excluded reservation is rejected. Reservations may be inside or outside pools;
the future allocator must exclude reservations from general allocation. Duplicate
interface bindings, overlapping subnets, network/broadcast addresses and an
unexcluded router inside a pool are rejected. Total declared pool capacity is
limited to 65,536 addresses before exclusions.

Options include gateway, up to four DNS and NTP servers each, a canonical ASCII
domain, and explicit lease/renew/rebind times. Leases range from 60 seconds to
seven days; renew must precede rebind, which must precede expiry. Schema 1 uses
MAC reservations; client identifiers, relay, DHCPv6, prefix delegation, custom
option blobs, dynamic DNS and HA are not supported by this contract.

`Decode` rejects oversized, unknown, duplicate and case-aliased control fields.
Call `Validate` with bindings derived from trusted inventory and selected network
configuration. Successful validation proves neither ownership of a live interface
nor the absence of another DHCP server. Disabled service configuration is retained
and still validated; it must produce no exclusive runtime resources.
MAC reservations are address-allocation preferences, not device authentication;
clients can spoof a MAC address.

Integration gates:

- Review engine licensing, offline dependency closure and measured resource cost.
  Kea is an existing candidate, not selected by this contract.
- Reuse the configuration coordinator, RBAC, audit and Web/CLI/API contracts.
  Keep local INPUT policies separate from forwarding and NAT.
- Preview changes; apply with confirmation, preserve running access, save
  explicitly, and qualify rollback without discarding issued lease ownership.
- Prove interface/namespace ownership and detect conflicting listeners before
  enablement. Never open WAN or imply Internet access from a DHCP lease.
- Test DORA, renewal, expiry, reservations, exclusions, pool exhaustion, restart,
  storage pressure and disabling against a real server and clients in isolation.

## Minimal Debian installation

Do not assume a DHCP server is installed. The eventual offline package must
include the selected engine and its full, architecture-compatible dependency
closure, with trusted repository provenance, a checksum manifest, SBOM and third-
party licenses. Installing the engine and enabling the feature are separate
operations. No runtime `apt` invocation or online download is permitted.

Debian 13 provides `kea-dhcp4-server`, with an exact-version dependency on
`kea-common` and additional shared libraries. This is a packaging candidate, not
an engine selection or an installed capability. Use component packages rather
than a metapackage that adds unrelated DHCPv6, DDNS or control-agent services.
See the [Debian package record](https://packages.debian.org/trixie/kea-dhcp4-server)
and [common library dependencies](https://packages.debian.org/trixie/kea-common).

Installation qualification must prove that package maintainer scripts cannot
start a competing DHCP service on host interfaces. Preserve existing service
policy and configuration; do not overwrite a machine's `policy-rc.d` or disable
unrelated services. Enablement requires validated ANDEIVA configuration and
owned service/namespace boundaries. Disabling must stop exclusive workers,
listeners and rules while retaining bounded lease data safely. Uninstall must
remove only owned runtime resources and preserve unrelated Debian packages.

Required packaging cases: clean minimal Debian with no server, offline install,
missing/corrupt/incompatible dependency refusal, pre-existing engine/service,
upgrade, interrupted installation, rollback and uninstall. Verify no DHCP reply
on any host interface before explicit enablement and none on WAN afterward.

Reproduce the currently executable checks without privileges:

```sh
go test -race ./internal/dhcpserver
go vet ./internal/dhcpserver
go build ./internal/dhcpserver
```

[Español](docs/es.md) · [Português](docs/pt.md)

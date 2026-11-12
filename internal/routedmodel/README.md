# Prepared routed configuration contract

This package contains the pure canonical IPv4 policy model used by the isolated
routed adapter. It performs no I/O and grants no permission to change networking.
`routednft` retains its public internal aliases and error identity; compilation
continues to produce the same revision, creation and replacement batch bytes.

`configpoc.CanonicalRouted` validates a prepared schema 6 envelope. It requires an
explicit lab-only policy, deny default, no legacy rules and no local-service
payload. The ordinary `Canonical` entry point still rejects this envelope, as do
the existing firewall, local-service and simulated engines. No journal reader,
API, transaction coordinator or deployed runtime is enabled for schema 6 here.

The model validates interface/zone bindings, ordered explicit enabled states,
IPv4 CIDRs and TCP/UDP port ranges. Unsupported protocols, required inspection
and invalid or ambiguous NAT/path references are rejected. These restrictions
describe the current experiment, not a production firewall capability.

From the repository root with its pinned Go toolchain:

```sh
go test -race ./internal/configpoc ./internal/routednft ./internal/localengine
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...
GOOS=darwin GOARCH=arm64 go build ./cmd/... ./internal/...
```

The routed-envelope tests include pre-extraction compiler digests, legacy hash
preservation, independent input copies and rejection by actual legacy consumers.
Compilation on another OS does not establish native runtime support. No host
interfaces, rules, routes or forwarding settings are changed by these tests.
See [Spanish](README_ES.md) and [Portuguese](README_PT.md).

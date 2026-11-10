# Local services: isolated compiler

This developer POC validates declarations and produces JSON; it installs nothing.
Run from the repository root with its pinned Go toolchain:

```sh
go test ./internal/localpolicy
go test -race ./internal/localpolicy
go vet ./internal/localpolicy
go test ./internal/localpolicy -run '^$' -bench BenchmarkCompile -benchmem
GOOS=windows GOARCH=amd64 go build ./internal/localpolicy
GOOS=darwin GOARCH=arm64 go build ./internal/localpolicy
```

The race detector requires a supported platform and C toolchain. No containers or
privileged network operations are necessary. Fuzzing is optional:
`go test ./internal/localpolicy -fuzz FuzzDecode -fuzztime 10s`.

Use `DefaultManagement` with a trusted LAN inventory entry, exact local address
and explicit source prefixes. It declares TCP 443 with required authentication.
It does not start HTTPS. Modify the service's `Bindings` to select one or several
LAN, WAN or other interfaces. WAN requires `WANOptIn: true` on each binding.
Bindings must match inventory zones and addresses. IPv4 and IPv6 require separate
bindings with matching source families. Wildcards and /0 sources are rejected.

`Canonical` validates and hashes an independent copy. `Compile` derives owned
rules and a new-table JSON batch. `Preview` identifies added/removed permissions
and flags administrative changes as requiring confirmation. `EffectiveView`
filters derived records by service; editing its output cannot change declarations.
`Reconcile` compares supplied observations, including missing or residual listeners
and rules. Its consistent result does not prove actual kernel state.

The table is `inet andeiva_local_poc`, input priority 10, default drop. Never apply
it on the appliance host. ICMP/IPv6 control traffic, loopback, administrative
recovery, actual authentication, socket inspection and atomic replacement are not
implemented. Other nftables base-chain drops remain effective. No forwarding or
NAT permission is generated. No command to install this POC is provided.

Tests cover declarations, conflicts, dependencies, port replacement, disabled
permissions, multiple interfaces, IPv4/IPv6, supplied-observation mismatch,
serialization and concurrent compilation. They do not demonstrate real traffic,
process failure recovery, Commit Confirmed, audit or persistent transactions.
Benchmark output measures compiler allocations and time only, not appliance RAM
or packet-processing performance.

There is no installed component to stop or uninstall. Update or remove this
package through the normal source review process. The next integration requires
approval of the [shared transaction design](../ADR.md), a trusted observer and
isolated Debian tests. System → Local Services and Firewall → Effective Policies
are planned Web/CLI/API views; they are not delivered by this package. VPN, DNS,
DHCP, NTP, portal, reverse proxy and WAF names reserve service identities only.

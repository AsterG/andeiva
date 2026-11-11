# Read-only interface inventory

`Discover(context.Context)` reads real interfaces, addresses and OS link flags. It
does not assign roles or zones, configure an interface, enable forwarding, start
workers or execute commands. The returned Go types are internal observations, not
an administrative API or a transaction schema.

Interfaces are sorted by index/name. Addresses are deduplicated and sorted without
masking their host bits. IPv4 and IPv6 are retained; an address supplied without a
mask has `Prefix == nil`. `AdminUp` and `Running` describe OS flags, not physical
carrier, connectivity, negotiated speed or Internet availability. Gateway, DNS,
DHCP/static provenance, routes and desired configuration are not inferred.

On Linux, classification reads fixed sysfs links. `device-backed` means that the
interface has a device link, including virtual PCI hardware presented to a VM; it
does not prove physical hardware. `virtual` identifies the kernel's virtual-net
path. Missing, unsafe or unavailable metadata remains `unknown`. Loopback is
identified from its OS flag. Other platforms keep classification unknown except
for loopback. No driver or operating-system version is exposed.

Two full observations must agree; otherwise `network_inventory_changed` is
returned without partial data. This detects observable changes, not every race or
an atomic kernel snapshot. Cancellation is checked between OS calls and cannot
interrupt a standard-library enumeration already in progress. Calls are stateless
and can run concurrently.

The retained result is limited to 256 interfaces, 256 addresses per interface,
256-byte names and 64-byte hardware addresses. Invalid/duplicate identities or
limits fail the entire observation. The standard library first allocates its OS
enumeration result; these limits do not cap that preliminary allocation. Errors
use stable inventory codes and do not expose raw syscall or filesystem details.
Cancellation or deadline expiry can also return `context.Canceled` or
`context.DeadlineExceeded`; consumers should distinguish these using `errors.Is`.

Run from the repository with its Go toolchain:

```sh
go test -race ./internal/networkinventory
go vet ./internal/networkinventory
go test -run '^$' -bench Discover -benchmem ./internal/networkinventory
GOOS=windows GOARCH=amd64 go test -c -o /tmp/networkinventory-windows.test.exe ./internal/networkinventory
GOOS=darwin GOARCH=arm64 go test -c -o /tmp/networkinventory-darwin.test ./internal/networkinventory
```

Tests cover invalid observations, bounds, changes, cancellation, concurrent calls,
safe classification and read-only Linux enumeration. Benchmarks distinguish
synthetic parsing from real OS enumeration. Runtime tests on another platform,
privileged configuration, network recovery and Web/CLI/API parity remain separate
integration gates. See the [Spanish](docs/es.md) and [Portuguese](docs/pt.md) guides.

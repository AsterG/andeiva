# Local-service fixture

`NewLocalOwned` creates three owned network namespaces using the existing
descriptor-based lifecycle. It creates no persistent namespace names and changes
no host interface, route, ruleset or sysctl. Existing `New`/`NewOwned` keep their
forwarding experiment behavior; the local constructor has a separate allowlist.

The gateway has `src0` and `dst0`, each connected only to its own source/sink
namespace. IPv4 links are `198.18.1.0/29` and `198.18.2.0/29`; gateway `.1`, primary
peer `.2`, alternate peer `.3`. IPv6 links are `fd42:616e:6465:1::/64` and
`fd42:616e:6465:2::/64`, with the same host numbers. Explicit link-local pairs are
`fe80::1`/`fe80::2` and `fe80::5`/`fe80::6`. Automatic link-local generation is
disabled only on these owned veths. Static IPv6 fixture addresses use `nodad` to
avoid setup timing dependence; this fixture is not evidence of real DAD handling.

No transit/default route or forwarding activation is issued. A subprocess reads
the isolated gateway forwarding settings and refuses initialization if forwarding
is enabled. `LocalInventory` and `LocalNeighbors` return independent copies of
the exact trusted inventory/profile consumed by `localnft.CompileWithNeighbors`.
Both logical links are laboratory LANs, unrelated to host WAN/LAN roles.

`StartLocalServices` launches only the current trusted executable's fixed
`--local-services HOST_INODE SUPERVISOR_PID` role in the retained gateway namespace,
as the configured unprivileged UID/GID with all capabilities dropped and
`no-new-privileges`. Its implementation must call `GuardLocalServices` before
handling input. The existing `StartGateway` retains its separate, narrow guardian
role with NET_ADMIN. Neither API accepts an executable path from an administrator.

The constructor starts no listener. `StartLocalEcho` explicitly launches a
transport-test echo process on gateway IPv4/IPv6 addresses and ports 18080–18082
(TCP and UDP). This is not HTTPS, SSH, DNS or any other service implementation.
It exits on supervisor input closure and is retained for `CloseOwned` cleanup.
`ProbeLocalGateway` accepts only fixed side/family/primary-or-alternate/protocol/
test-port selectors. It binds the exact chosen source and exchanges a random
64-byte nonce with its directly attached gateway. It accepts no destination IP,
shell command, arbitrary port, or route. A timeout is a denied observation;
connection refusal and other local errors remain errors rather than policy proof.

Keep positive echo controls separate from real authenticated HTTPS/SSH tests.
`ClearLocalNeighbors` flushes IPv4/IPv6 neighbor caches on exactly the four owned
veths, only in local mode. Use it before claiming cold-neighbor coverage in an
authorized native test. Always compare host/sentinel baselines and run `CloseOwned` after stopping
the API/helper; it closes only retained processes and namespace handles.

Unprivileged verification:

```sh
go test ./internal/nftfixture
go test -race ./internal/nftfixture
go vet ./internal/nftfixture
```

Command-plan and parser tests do not execute namespace changes. Real traffic,
kernel readback, resource measurements and failure recovery require the authorized
Debian 13 laboratory and must be recorded separately.

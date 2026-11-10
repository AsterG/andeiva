# Local service activation coordinator

This package joins the Local-In ruleset and the unprivileged HTTPS/SSH listener
lifecycle as one engine for the existing configuration transaction coordinator.
It does not execute commands, authenticate administrators or install services.

The trusted constructor pins interface inventory and the IPv6 neighbor profile.
Activations accept schema 3 with local-service declarations and an empty forwarding
policy, or legacy schemas with no managed local services. A fresh executor cannot
adopt an existing table by name. Its transport must attest the owned namespace and
use only the fixed `andeiva_local` table.

The engine validates and checks the batch, applies the rules, replaces listeners
and reads both effective components before publishing a revision. A listener
replacement must terminate obsolete connections as well as listening sockets.
Kernel rules can change atomically; the combined socket/rule transition is not
atomic and can temporarily interrupt managed access. An independent, authenticated
recovery endpoint is required. No temporary broad permission is introduced.

Errors and lost acknowledgements never publish the target. The independent lease
guardian may compensate with its previously authorized revision. If it cannot
verify both components, recovery remains blocked. A process restart cannot assume
listener restoration from a saved declaration. Every observation must check actual
namespace-scoped sockets and ownership, rather than a cached listener list.

Tests use injected kernel/listener fixtures to exercise failures, lost replies,
drift, unsupported inventory/forwarding, legacy removal and concurrent reads.
They are not evidence of Debian packet filtering or a working protocol server.
Native adapters, real listener authentication and traffic qualification remain
separate acceptance gates.

```sh
go test -race -count=1 ./internal/localengine ./internal/localnft
go vet ./internal/localengine ./internal/localnft
```

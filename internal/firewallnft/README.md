# Administrative lab policy compiler

This package compiles schema 2 configurations for one isolated gateway namespace.
It is not an appliance firewall, identity engine, inspection engine or production
permission to forward unknown traffic. The privileged helper must bind its own
namespace identity, executable, interfaces and table; callers cannot select these.

The compiler owns only `inet andeiva_admin`, with a default-drop forward chain.
Ordered rules contain canonical IPv4 CIDRs, TCP/UDP and explicit nonzero source
and destination port intervals. Every rule emits a forward/reverse pair. Explicit
deny pairs preserve first match. IPv6 and unmatched protocols receive no allow.

An allow reevaluates the full tuple and `src0`/`dst0` interfaces on every original
packet, requires conntrack original direction and new/established state, then sets
the namespace-owned admission mark. Replies require the reversed current tuple,
reply direction, established state and the admission mark. There is no global
established/related acceptance. Deletion, narrowing and an earlier deny revoke
matching return permission immediately at policy replacement. A new allow for
the same tuple intentionally permits an already admitted connection. Marks are
not revision hashes, identities or authorization outside the current tuple rules.
No NAT, asymmetric routing, conntrack helpers or shared mark ownership is supported.

`Compile` returns canonical revision, SHA-256 batch digest and bounded JSON
create/replace batches. `New` uses the shared `nftengine` transition adapter,
retaining check-before-apply, independent readback after uncertain responses and
reconciliation restricted to known transition outcomes. The original `nftpoc`
package uses the same adapter while retaining its immutable schema 1 catalog.

`InspectObservation` reconstructs the canonical policy, verifies the revision
comment, expression semantics and order, and returns at most 64 rule counters.
Duplicate JSON keys, extra objects/expressions, missing guards, counter overflow
and foreign tables fail closed. Only nft 1.1.3 redundant protocol dependency
elision is normalized. Counter totals aggregate both directions and reset on
atomic replacement. They are packet totals, not per-flow traffic logs. Public
adapters must expose only authorized functional data, not raw kernel JSON.

Syntax references: the pinned upstream nftables 1.1.3 `tests/py/any/ct.t.json`
and `.json.output`, and `tests/py/inet/meta.t.json.output`; JSON expressions follow
[libnftables JSON](https://manpages.debian.org/trixie/libnftables1/libnftables-json.5.en.html).

Reproduce unprivileged checks from the repository root:

```sh
go test -race ./internal/nftpoc ./internal/firewallnft ./internal/nftengine
go vet ./internal/nftpoc ./internal/firewallnft ./internal/nftengine
go build ./...
```

Unit tests cover semantic readback mutation, tuple/order enforcement, unsolicited
reverse traffic, markless established flows, invalid/untracked/related state,
revocation, counters and v1 compatibility. Their packet interpreter is not kernel
evidence. Native isolated nft 1.1.3 checks, live negative probes, resource
benchmarks and independent review remain required before any completion claim.
Rollback is the coordinator's previous canonical revision, compiled into an atomic
table replacement; no host networking or customer appliance changes are involved.

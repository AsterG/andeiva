# Administrative lab policy compiler

This package compiles schema 2 and schema 4 configurations for one isolated gateway namespace.
It is not an appliance firewall, identity engine, inspection engine or production
permission to forward unknown traffic. The privileged helper must bind its own
namespace identity, executable, interfaces and table; callers cannot select these.

The compiler owns only `inet andeiva_admin`, with a default-drop forward chain.
Ordered rules contain canonical IPv4 CIDRs, TCP/UDP and explicit nonzero source
and destination port intervals. Every enabled rule emits a forward/reverse pair. Explicit
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

For schema 2, `InspectObservation` reconstructs the canonical policy, verifies the revision
comment, expression semantics and order, and returns at most 64 rule counters.
Duplicate JSON keys, extra objects/expressions, missing guards, counter overflow
and foreign tables fail closed. Only nft 1.1.3 redundant protocol dependency
elision is normalized. Counter totals aggregate both directions and reset on
atomic replacement. They are packet totals, not per-flow traffic logs. Public
adapters must expose only authorized functional data, not raw kernel JSON.

Schema 4 requires an explicit `enabled` boolean on every rule, including disabled
rules. All rules retain their order and receive the same validation and 64-rule
limit. Disabled rules emit no kernel rules or counters. `VerifyObservation` checks
the entire effective projection against a trusted complete revision; a table
comment alone cannot recover disabled configuration. `Engine.Inspect` uses that
verified readback. An unknown schema-4 kernel policy is not adopted on startup.
Schema 1–3 serialization remains unchanged; migration from schema 2 is an explicit
Candidate change, followed by the existing validation/commit/save flow. Schema 4
does not carry LocalServices and is rejected by the local-service domain.

The authenticated capabilities response advertises
`firewall_config_schema_versions: [2, 4]` and `firewall_rule_enabled: true` only
when the runtime explicitly enables support. Older runtimes remain at schema 2.
Traffic history retains prior observations; disabling produces no synthetic zero
record, and reenabling starts a new baseline. Native traffic and resource gates
for this extension remain pending; unit tests are not appliance evidence.

### Español

El schema 4 exige `enabled` explícito en cada regla. Las reglas desactivadas
conservan orden, validación y el límite total de 64, pero no generan reglas ni
contadores en el kernel. La revisión completa confiable permite verificar la
política efectiva; el comentario de una tabla no basta. La migración desde schema
2 es un cambio explícito de Candidate, con Validate/Commit/Save y rollback del
coordinador existente. Los schemas 1–3 conservan su serialización; schema 4 no
incluye LocalServices. El soporte debe anunciarse mediante capacidades del runtime.
La reactivación inicia una nueva línea base de contadores. La validación nativa y
las mediciones de recursos de esta extensión siguen pendientes.

### Português

O schema 4 exige `enabled` explícito em cada regra. Regras desativadas preservam
ordem, validação e o limite total de 64, mas não geram regras nem contadores no
kernel. A revisão completa confiável permite verificar a política efetiva; o
comentário de uma tabela não basta. A migração do schema 2 é uma alteração explícita
de Candidate, com Validate/Commit/Save e rollback pelo coordenador existente.
Os schemas 1–3 preservam sua serialização; schema 4 não inclui LocalServices.
O suporte deve ser anunciado pelas capacidades do runtime. A reativação inicia
uma nova linha de base dos contadores. A validação nativa e as medições de recursos
desta extensão continuam pendentes.

### Validation and references

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

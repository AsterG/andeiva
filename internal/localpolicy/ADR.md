# Local service policy compiler and transaction boundary

Status: proposed extension; the isolated compiler is implemented. A shared
configuration schema change and runtime integration are not approved by this ADR.

## Scope and threats

Traffic addressed to ANDEIVA belongs to the local-input domain. Transit traffic
belongs to the forwarding domain. Enabling a local service must never generate a
forwarding permission. The immediate scope is a pure Go compiler and tests,
without processes, listeners, privileged commands or kernel changes.

The primary threats are unintended WAN exposure, source-scope expansion, stale
permissions after disabling a module, listener conflicts, administrative lockout,
forged observations and publishing an unverified revision. Validation rejects
unknown fields and versions, duplicate/case-variant JSON keys, excessive nesting,
wildcard interfaces/addresses, unregistered local
addresses, empty source lists, unrestricted /0 sources, mixed address families,
overlapping endpoints/sources and inconsistent dependency graphs. Exact local
addresses avoid ambiguous wildcard socket overlap in this version.

## Contract

Schema 1 contains an authoritative interface inventory and owned service
declarations. Each binding selects an interface, its inventory zone, one local
address, explicit source prefixes and an explicit WAN opt-in. Interfaces can be
LAN, WAN or other; one service can select several interfaces and both address
families. `DefaultManagement` requires a LAN interface and caller-supplied source
prefixes. Explicit WAN-only and LAN+WAN declarations are supported. No runtime
interface selector or management listener reconfiguration is implemented here.

Declarations cover ownership, TCP/UDP ports, supported zones, authentication,
enabled state, dependencies and mandatory listener/rule verification and failure
reversion. Management changes require confirmation. These are requirements on a
future deployer, not evidence that authentication or rollback occurred. Service
kinds for VPN, DNS, DHCP, NTP, portal, reverse proxy and WAF reserve identities;
they do not implement those engines. Arbitrary IP protocols, multicast/bootstrap
DHCP, wildcard listeners and shared sockets are outside this compiler's scope.

Canonical revisions bind inventory, declarations and lifecycle requirements.
Administrative impact includes the transitive dependency graph, even when the
administrative listener declaration itself remains unchanged.
Generated rule IDs bind owner, service and exact permission. Disabled modules
produce no exclusive permissions. Preview reports additions and removals,
including retired ports. Effective records are derived values, never editable
policy input. Ownership changes need authorization in the future registry; this
pure package cannot authenticate callers.

## nftables boundary

The compiler emits JSON to create the `inet andeiva_local_poc` table, with an
`input` filter base chain at priority 10 and default drop. Each allow is scoped to
interface, IP family, local destination, source prefix, TCP/UDP and destination
port. There are no forwarding, NAT or output rules, established-connection bypass,
shell commands, host flushes or replacement operations.

Priority 10 follows ordinary priority-0 filter chains. An accept verdict does not
bypass a drop in another base chain; all relevant chains still matter. A drop is
terminal. This does not establish a universal ordering against arbitrary host
rules: activation must inventory chains and reject conflicting ownership/order.
See the [nftables chain documentation](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains).

This batch is for an isolated namespace only. It is **not safe to install on the
appliance host**: ICMP/ICMPv6 control traffic, loopback and administrative recovery
are not covered. An all-disabled declaration still compiles the prospective
shared default-drop chain; it starts no engine and installs no hook. It is not a
module enable operation. Kernel syntax checking, atomic replacement, real rule
readback and real connectivity tests remain required before any activation.

`Reconcile` compares trusted caller-supplied, namespace-scoped listener and rule
observations against a revision. Missing, extra, duplicate, stale and mismatching
records are reported. Equality is not proof of kernel state, process identity,
authentication, base-chain ordering or connectivity. A future collector must
verify those independently; the coordinator must not confirm from equality alone.

## Reuse of the transaction engine

The existing `configpoc.Config` schema represents forwarding rules. Its engine
contract takes that shared revision. Encoding local service rules as forwarding
rules or maintaining a second coordinator would break domain separation and
atomic publication. Neither is done here.

Proposed next step: approve a schema-3 configuration envelope with explicit
`forwarding` and `local_services` domains under the existing single coordinator.
Review migrations from schemas 1/2, deterministic hashing, RBAC, audit event
compatibility, storage limits, resource budgets and Web/CLI/API contracts before
changing the shared schema. A generic opaque engine payload is an alternative,
but would move validation and compatibility guarantees outside the canonical
model; it is not selected without that review.

The future bridge must stage Candidate, validate both domains, journal intent,
coordinate listener and policy changes with safe ordering, observe the kernel,
then publish Running. Save alone updates Startup. Confirmed administrative
changes need an independent connectivity challenge and durable timeout reversion.
Unknown apply results must block new operations until reconciled, never publish
an unverified revision. Recovery must restore listeners and policies together.

| Gate | Current evidence |
| --- | --- |
| Typed validation, deterministic compilation, impact | Pure unit tests |
| IPv4/IPv6 scope and multiple interface declarations | Pure unit tests |
| Disabled permissions and supplied-observation drift | Pure unit tests |
| Candidate/Running/Startup bridge, audit, RBAC | Pending shared-contract review |
| Commit Confirmed, rollback, restart, process failure | Pending bridge and real laboratory tests |
| Listener verification and administrative lockout recovery | Pending trusted observer and connectivity tests |
| Web/CLI/API operations and read-only effective views | Planned, not exposed |
| Kernel syntax, real IPv4/IPv6 traffic and resource overhead | Pending isolated Debian execution |

## Administrative presentation

Future service screens own ports, interfaces and authorized sources. System →
Local Services lists declarations. Firewall → Effective Policies filters derived
rules by service, owner and revision, without editing generated rules. Ordinary
Firewall Security Policies remain the forwarding domain. Web, CLI and API must
share validation, permissions and transaction operations when integrated.

## Rollback of this change

Remove the unused package to undo this isolated compiler. It has no runtime
registration, external dependencies, background workers or persistent state.
This is not an appliance recovery procedure or a production-readiness claim.

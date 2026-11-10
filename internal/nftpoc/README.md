# Isolated nftables transaction experiment

Status: bounded laboratory validation completed on Debian 13 AMD64. This is an
experimental adapter, not a production firewall. See [validation](VALIDATION.md)
for tested scenarios, resource observations and remaining failure boundaries.

This laboratory adapter connects the existing configuration transaction service to
one bounded nftables policy. It is not the appliance firewall or a production
management interface. Privileged execution is restricted to the authorized Debian
13 laboratory; ordinary unit tests and shared CI runners use an in-memory transport.

Procedures: [English](docs/en.md), [Español](docs/es.md), [Português](docs/pt.md).
The validation report identifies the tested source and actual results. Preserve
private execution evidence separately; instructions alone do not prove success.

## Typed policy and kernel observation

The existing `configpoc` schema remains version 1. The adapter accepts only an
immutable, versioned fixture catalog. Each rule identifier binds a catalog digest
to an explicit IPv4 source, destination, protocol and service port. Unsupported
identifiers, duplicate identifiers, invalid actions and a non-deny default are
rejected. No caller-supplied nft expression, executable, path or table is accepted.

| Fixture | Source | Destination | Service |
| --- | --- | --- | --- |
| `tcp.a`, `udp.a` | `198.18.0.2` | `198.18.0.6` | TCP or UDP 18080 |
| `tcp.b`, `udp.b` | `198.18.0.2` | `198.18.0.6` | TCP or UDP 18081 |
| `tcp.a.second`, `udp.a.second` | Same fixed endpoints | Same fixed endpoints | Ordered first-match experiments on 18080 |

Each logical rule expands into explicit request and return selectors using the
fixture's `src0` and `dst0` gateway links. Return selection uses the service's
source port; this experiment does not implement connection tracking. TCP and UDP
18082 are reserved for probes that must remain denied in every catalog policy.
The gateway's `inet andeiva_poc` forward chain has a fixed drop policy. IPv6 and
every other tuple are outside the allowed fixture policy.

Compilation binds the logical configuration revision, catalog and compiler version
to the exact JSON batch digest. Bootstrap creates the owned table once. Replacement
deletes and recreates only that table in one batch, after `nft --check`. It never
flushes the host ruleset or adopts a pre-existing unregistered table.

Readback verifies the table, chain, hook, priority, policy, rule order, selectors,
interfaces and verdicts. Comments identify candidate catalog rules but cannot
prove their semantics. Only known kernel handles and bounded version metainfo are
excluded from comparison. Equivalent nftables 1.1.3 representations (numeric
transport protocol and omission of redundant protocol selectors) are accepted
only with the complete expected IP/interface/port/verdict structure.
Unknown objects or expressions, duplicate JSON keys,
extra fields, malformed data and oversized output are rejected.

## Transaction and privilege boundaries

Candidate, Running, Startup, authorization, idempotency, concurrency and journal
audit remain the responsibility of `configpoc.Service`. Running advances only
after the adapter acknowledges an exact observed revision. An uncertain dispatch
retains its previous and target hashes: compensation can reconcile either known
outcome, while an unrelated revision is rejected as drift.

A short-lived supervisor creates three private network namespaces and pinned
namespace handles. Source and sink are connected only through the private gateway;
no physical interface, host bridge or external route participates. The supervisor
owns setup and cleanup. The coordinator and traffic processes are unprivileged.
A separate helper operates within the verified gateway namespace and accepts
bounded typed requests through private local channels. It recompiles the policy
and invokes the fixed nft executable with controlled arguments and standard input.

Commit Confirmed additionally requires the independent helper's rollback lease.
Killing the coordinator must not stop that lease. A durable service confirmation
and a matching helper acknowledgment are both required before the runner reports
confirmation. Expiry or a lost acknowledgment requires reconciliation. Loss of
the helper or complete supervisor is a separate failure boundary, not a proven
power-loss or appliance-reboot guarantee.

An uncertain confirmation blocks every subsequent mutation, including Save and
recovery requests. The block is lifted within that operation only if the helper
proves the exact confirmed lease and target and the effective revision matches.
An unverifiable or malformed channel stays unusable. Restart reconciles the
durable journal before releasing the helper's rollback barrier. The journal's
confirm receipt records its own persistence boundary; the coordinator trace
separately reports helper acceptance or required recovery.

The supervisor self-exec has one narrowly reviewed G204 exception: executable
and role are fixed, arguments are checked identifiers and an owned private state
directory, and credentials are dropped before execution. No global scanner rule
is disabled. The helper verifies UID, namespace, `NoNewPrivs` and exactly
`CAP_NET_ADMIN` before invoking nftables. UID 1000 shares the trusted laboratory
operator's trust domain; this is not a production authorization boundary.

## Validation scope

Unprivileged tests cover catalog validation, deterministic compilation, semantic
readback, drift, bounded own-outcome reconciliation, concurrent adapter access and
integration with the real journal using a simulated nft transport. The privileged
laboratory runner must separately establish actual kernel behavior and TCP/UDP
delivery, with healthy listeners and independent positive controls.

Preserve the private report, source digest, timings, audit and host baseline
comparison. CPU/RSS observations must identify which processes they cover; they
are not a throughput benchmark or a whole-appliance capacity claim. No privileged
network experiment may run on a shared GitHub Actions runner.

This POC does not provide NAT, VPN, IPS, proxy, WAF, antivirus, HTTPS inspection,
HA, production authentication, a deployed Web/API/CLI configuration surface,
signed packages or power-loss resilience. Web/CLI/API labels exercise the same
service permission contract; they are not authenticated transport implementations.

Removing the experimental binary is the installation rollback. Preserve reports
before removing their explicitly identified directories. Do not downgrade an
existing configuration journal using an older binary or clear unknown resources
to force a test to pass.

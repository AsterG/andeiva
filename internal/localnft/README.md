# Local-In runtime compiler

This package performs no I/O or privileged execution. It compiles the canonical
`localpolicy.Config` and verifies a complete JSON listing of the isolated
`inet andeiva_local` table. It does not prove listener health, authorize a caller,
select a namespace, or publish a transaction. Those are executor/coordinator
responsibilities.

## Scope and ownership

The only base chain is `input`, filter priority `10`, policy `drop`. Earlier or
later base chains can still reject packets; an accept here cannot override a
drop elsewhere. No OUTPUT, FORWARD, NAT, routing, broad established-connection,
loopback, or general ICMP allowance is generated. `Create` creates the owned
table; `Batch` atomically deletes and recreates exactly that table. The executor
must verify ownership and current state before choosing either batch, run
`nft --check`, and verify a fresh effective listing after applying it. Never use
these batches in the host namespace.

`ValidateManaged` limits real engines to one HTTPS and one SSH service, singleton
TCP ports at least 1024, and non-link-local management addresses. `Compile` also
accepts UDP declarations for transport fixtures; that is not DNS/VPN engine
support. All source/interface/address permissions come from validated service
declarations and trusted interface inventory. Disabled services generate no
service rules.

Capacity: two services, two interfaces, four addresses per interface, four
bindings per service, sixteen source prefixes per binding, one endpoint per
service, 128 permission rules and at most 136 control rules. Configuration is
limited to 24 KiB, generated batches to 384 KiB, and observations to 512 KiB.
These bounds do not constitute an IPC framing guarantee for the caller's full
transaction envelope; previous/target/profile envelopes must also be tested.

## IPv6 neighbor discovery

`Compile` has no ND exceptions. `CompileWithNeighbors` accepts a separate immutable
executor-owned profile: exact IPv6 local/peer addresses on each owned interface,
including explicit link-local addresses when needed. Local addresses must exist
in trusted inventory. This profile is not editable through a service declaration.
Its canonical form is included in the artifact digest even while inactive. The
executor must bind it to run metadata and reject a changed profile on recovery.
The service revision hash remains the canonical service configuration hash.

For interfaces with enabled IPv6 bindings, rules admit only ICMPv6 neighbor
solicitation/advertisement, code zero and hop limit 255. NS targets exactly an
owned local address, with exact local or corresponding solicited-node destination
and an explicitly listed peer source. DAD permits source `::` only to that
solicited-node destination and local target. NA source and target are the same
explicit peer; destination is an owned local address or link-local all-nodes.
There is no inferred subnet, router advertisement, redirect, echo or general
link-local permission. ND rules disappear when no IPv6 service remains enabled
on that interface. Their `andeiva-nd:` IDs and counters are separate from service
permission records. An unauthorized service client may be an explicit ND peer:
neighbor resolution then succeeds while TCP/UDP access is still denied.

This is a bounded point-to-point laboratory profile, not a general NDP security
solution. It does not authenticate peers, prevent all neighbor spoofing, provide
router discovery or enable arbitrary IPv6 networks. The typed `icmpv6 taddr`
selector is documented in the [nftables manual](https://netfilter.org/projects/nftables/manpage.html).
Native parser/readback and cold-neighbor tests remain required on the target.

## Observation and failure behavior

`VerifyObservation` recompiles the configuration and trusted profile independently
and checks the complete expected artifact. It compares table/chain properties,
every ordered rule expression and comment. Unknown fields/objects, duplicate JSON
keys, excess depth/size, missing/extra rules, invalid counters and altered targets
fail closed. Only validated unsigned handles and bounded metainfo are ignored.
Counters retain exact `uint64` values; no floating-point conversion or fabricated
zero observation is used. `ReadbackHash` hashes the exact verified input bytes.

The observer accepts only explicit equivalent nft serialization variants:
redundant family/transport guards implied by typed payloads may be omitted;
transport numbers and NS/NA symbolic names may replace their exact equivalents.
All interface, address, source, port, hop-limit, code and target predicates remain
mandatory. New normalization behavior must be demonstrated and reviewed before
being accepted. A mismatch must block publication and invoke the coordinator's
recovery contract; comments alone never establish successful application.

## Reproduction

```sh
go test ./internal/localnft
go test -race ./internal/localnft
go vet ./internal/localnft
go test ./internal/localnft -run '^$' -bench . -benchmem
```

Unit observations are generated fixtures, not evidence of a running kernel or
real traffic. This package is not a production firewall implementation.

# Routed firewall and SNAT laboratory

Native Debian 13 namespace traffic tests and independent security review passed.
Sustained throughput and dataplane resource qualification remain pending.
This is an internal experiment; no Web/CLI/API, persistence or packaging adapter
is activated. It does not establish production routing, identity or inspection.

## Design and threat boundaries

The internal typed policy binds a canonical `networkplan.Revision`, explicit
interface/zone pairs, ordered allow/deny IPv4 CIDRs and TCP/UDP port ranges.
Every rule requires an explicit `enabled` boolean. Disabled rules retain their
complete validated configuration in the revision hash, but produce no kernel
rules or counters. Existing 1–64 character alphanumeric/dot/underscore/hyphen IDs
are preserved without renaming; they must start with an alphanumeric character.
Unsupported protocols, management paths, invalid references, duplicate IDs,
colliding rule marks and mandatory identification/inspection requirements are
rejected. `lab_only` must be explicitly true. Unknown traffic receives no implicit
exception or inspection claim. The lab's explicit TCP/UDP test traffic is the only
permitted traffic. NAT cannot authorize forwarding.

The exclusive `inet andeiva_routed_alpha` table has a forward hook at priority 0,
default drop (including IPv6), and a separate NAT postrouting hook at priority 100.
There are no input/output hooks. Rules reevaluate conntrack's original tuple on
every original and reply packet. This preserves scope across SNAT. Replies need
an admission mark belonging to that current complete rule and established state.
A matching rule with an invalid state/mark drops rather than falling through.
Reordering, tightening and removing rules therefore cannot use a broad established
exception to evade the current policy. Marks are bounded admission hints, never
identity/authentication; collision rejection and current tuple/policy checks are
both required. No blanket established/related accept exists.

RELATED is limited to ICMP destination-unreachable, time-exceeded and
parameter-problem errors, with the parent's original IPv4 tuple, protocol/ports,
current rule mark, interface pair and direction. Echo, redirects, untracked and
unrelated errors have no exception. The native runner checks a real UDP port
unreachable and its exact related-rule counter. Other ICMP types and PMTU cases
still need a larger negative/MTU integration matrix before a release claim.

`nftengine.Transport` is reused. The small adapter serializes observation,
check-before-apply, atomic table replacement and full semantic readback. It
retains only authorized before/target outcomes following lost acknowledgements.
It never authenticates a revision solely through its table comment. Readback
rejects extra objects/expressions, changed order, duplicate JSON fields, malformed
counters and oversized input; numeric protocol symbols, implied IPv4 guards and
kernel handles have narrowly defined normalization. Counters reset on replacement.

The fixed runner checks Debian 13 amd64/root, creates exactly three random
`andrt-...-{l,g,w}` namespaces, creates veths inside them and changes forwarding
sysctls only inside the gateway namespace. It verifies namespace inode ownership
before effects/cleanup and resolves name/MAC/index through trusted
`networkinventory.Discover` + `networkplan.Bind` before each transport operation.
Executables are allowlisted, output/deadlines bounded, and no shell is used.
Host IPv4/IPv6 routes and stateless nftables are captured read-only and compared after
cleanup. Concurrent external host policy changes will also fail this invariant.

## Reproduce

Unprivileged Linux/WSL source checks (Go 1.27.4 and an offline module cache):

```bash
go test -race ./internal/routednft ./cmd/andeiva-routing-lab
go test ./internal/routednft -run '^$' -fuzz FuzzReadback -fuzztime=10s -parallel=2
go vet ./internal/routednft ./cmd/andeiva-routing-lab
go test ./internal/routednft -run '^$' -bench . -benchmem
go build -trimpath -o /tmp/andeiva-routing-lab ./cmd/andeiva-routing-lab
/tmp/andeiva-routing-lab > /tmp/andeiva-routed-create.json
```

Only after independent review, inside an explicitly authorized disposable Debian
13 amd64 VM with a recovery snapshot, `iproute2`, `nftables`, root access and a
trusted copy of the built binary:

```bash
sudo /tmp/andeiva-routing-lab --run-isolated-lab
```

The runner exercises real SNAT TCP/UDP (server observes WAN source), related ICMP,
IPv6 forward denial with a counter, unsolicited reverse denial with a live LAN
server and valid return route, revocation of an already open TCP socket, routing
without NAT (server observes LAN source), and NAT without forwarding permission.
Any failed check returns nonzero. It emits semantic counters and cleanup/host
invariant results. Do not run on a customer appliance or Windows host.

Rollback is deletion of only this invocation's inode-matching namespaces after
stopping its children; success, ordinary failure, timeout, SIGINT and SIGTERM use
that same cleanup. SIGKILL, host crash or a substituted namespace may leave
objects behind. The printed namespace names identify the invocation for manual
ownership verification; never remove an existing namespace solely by prefix.
No host route/NAT/SSH restoration is needed because they are never mutated.

## Acceptance evidence and remaining gates

Unit tests cover input rejection, semantic drift, NAT separation, check failure,
lost acknowledgement, concurrent application and fuzzed observations. The runner
is source-reviewed separately before any privileged execution. SAST has two
documented G204 suppressions at fixed-command seams; no global rule exclusion.
No new dependency or license is introduced. Docker/EKS runtime changes: none;
this root-only namespace fixture is not a container service or deployment change.
Native packet tests in three isolated Debian 13 namespaces passed: TCP/UDP SNAT
with server-observed translated source, tuple-bound related ICMP, counter-verified
IPv6 denial, unsolicited reverse denial, revocation of an existing TCP socket,
routing without NAT preserving source, and NAT without forwarding authorization.
Namespace cleanup and external IPv4/IPv6 route/nft comparisons passed. The host's
forwarding settings stayed disabled. Test process: 3.635 s elapsed, 0.312 s CPU,
30,273,536-byte cgroup memory peak including child processes/cache; this is not
steady-state daemon RSS, throughput, or packet-latency qualification.

Unit/race/fuzz/vet/build, SAST, secret checks and independent security review
passed. Native validation found and corrected three interoperability faults:
original transport context versus ICMP, ICMP membership expressed as a bitmask,
and ambiguous legacy conntrack address selectors. Explicit IPv4 conntrack keys
preserve prefixes; exact numeric ICMP sets preserve membership. Readback accepts
only observed equivalent protocol/state/direction representations and implied
protocol guards. It never rewrites addresses, ports, marks or verdicts.

Remaining gates: wider RELATED/PMTU negative tests, translated conntrack-session
enumeration, sustained resource/traffic measurements, transaction integration,
Web/CLI/API parity and permanent deployment. Counters are kernel aggregates,
not per-flow logs. This laboratory adapter is not a production firewall.

Schema source: [official nftables manual](https://netfilter.org/projects/nftables/manpage.html).
Translations: [Español](docs/es.md), [Português](docs/pt.md).

# Read-only routed flow observation

Task: `ROUTING-ALPHA-001/routed-flow-observation`. Owner: network implementation.
Internal laboratory module, ready for source review; native transport/traffic and
resource qualification remain pending. No Web/CLI/API adapter, persistence,
packaging, engine activation or public operational capability is added.

## Design and threat analysis

`Collect(context.Context)` requests one IPv4 conntrack dump through
`NETLINK_NETFILTER` in the **current** network namespace. It has no namespace name
or file-descriptor input, setns, subprocess, shell, routing/NAT mutations,
sysctl/configuration writes, counter reset, packet capture or userspace packet
processing. The sole request is `CT_GET | REQUEST | DUMP`; it never uses NEW,
DELETE or GET_CTRZERO. The socket is private, nonblocking, close-on-exec and has
no multicast subscriptions. The trusted launcher owns namespace selection,
dependency preparation, privileges, output bounds and process lifetime.

The collector requires `/sys/module/nf_conntrack_netlink` to exist before opening
its socket. It does not try to load a missing component or retry with an alternate
engine. The authorized Debian lab currently reports that component absent;
preparation and native validation belong to the orchestrator. Built-in kernels
without that sysfs directory are conservatively unsupported by this guard.

The decoder checks kernel sender port/group, local port ID, nonzero sequence,
multipart flags/type, header/attribute lengths, nested/scalar flags, duplicate
semantic attributes and duplicate connection tuples. It rejects MSG_TRUNC,
ancillary truncation, overruns, interrupted dumps and malformed terminators.
ENOENT is unavailable, never a successful empty dump. Unknown attributes are
bounded and structurally checked, then ignored; their contents are not exported.
Explicit zero-length padding attributes may repeat only in their UAPI-defined
counter/timestamp groups. Header/TLV fields use native endianness; addresses,
ports, status, IDs, zones, timeout and counters use network byte order.

Hard bounds: 64 KiB/datagram, 4 MiB/dump, 8192 messages, 4096 reported flows,
256 attributes/record, six nested levels and two seconds total. Cancellation is
checked around every operation and at least every 50 ms during socket polling.
Any error returns no snapshot, including after some records have been decoded.
This is a bounded complete multipart dump, **not an atomic view** during traffic
churn. The collector does not silently return a truncated subset on resource
pressure. The launcher must consume/bound JSON stdout and enforce its own process
deadline; no live namespace names or arbitrary command strings are accepted.

## Evidence semantics

Only IPv4 TCP/UDP flows are reported. Other IPv4 protocols are counted as skipped,
without claiming classification or authorizing any packet. Each flow preserves:

- `original` and `reply`: exact kernel tuples, including ports and optional
  directional conntrack zones.
- `forward_translated`: inverse of the reply tuple; `reply_translated`: inverse
  of the original tuple. These derived endpoint views describe translation
  recorded in conntrack, rather than a live packet capture or current policy.
- `source_changed`/`destination_changed`: comparisons between original and
  translated forward endpoints. False does not exclude an identity NAT mapping.
- Optional raw status, mark, connection ID, conntrack zone, timeout seconds and
  TCP state supplied by the kernel. TCP state is not a firewall authorization
  state; UDP has no fabricated TCP/established state. Unknown TCP values retain
  their number with the name `unknown`.
- Optional original/reply packet and byte counters. Missing fields remain absent,
  distinct from a reported zero. `width_bits` identifies 32-bit legacy or 64-bit
  values; mixed/conflicting widths are rejected. Packet/byte counts are decimal
  strings on JSON wire and remain numeric `uint64` pointers internally, preserving
  exact values beyond JavaScript's 2^53 limit. Numeric counter JSON is rejected.
  No rate, latency, application,
  username, policy identity or inspection result is inferred.

Conntrack zones are kernel tuple namespaces, not ANDEIVA security zones. Derived
translated tuples deliberately do not invent zone assignments. Collection start
and finish are local clock readings, not trusted event timestamps. Presence of a
flow or admission mark never proves that current firewall rules still allow it.
The observer neither releases unknown traffic nor relaxes identification or
mandatory inspection. Nothing enables conntrack accounting when it is absent.

All output is sensitive platform evidence. A future adapter must require Platform
Super Administrator authorization on the server across every API/CLI/export/job,
plus privacy, audit and retention controls. No ordinary admin surface is wired.
Stable machine error codes avoid raw kernel diagnostics and endpoint disclosure
on failure. JSON is emitted once for a completed dump, not persisted or logged.

## Reproduce source checks

Go 1.27.4 with the existing offline module cache; no dependency changes:

```bash
go test -race ./internal/routedflow ./cmd/andeiva-flow-lab
go test ./internal/routedflow -run '^$' -fuzz FuzzMultipart -fuzztime=10s -parallel=2
go test ./internal/routedflow -run '^$' -fuzz FuzzFlowAttributes -fuzztime=10s -parallel=2
go vet ./internal/routedflow ./cmd/andeiva-flow-lab
go test ./internal/routedflow -run '^$' -bench . -benchmem
go build -trimpath -o /tmp/andeiva-flow-lab ./cmd/andeiva-flow-lab
GOOS=linux GOARCH=arm64 go build ./cmd/andeiva-flow-lab
GOOS=windows GOARCH=amd64 go build ./cmd/andeiva-flow-lab
GOOS=darwin GOARCH=arm64 go build ./cmd/andeiva-flow-lab
```

Tests use synthetic UAPI datagrams and fake transports. The Linux cancellation
tests stop before opening or using any real socket. They cover SNAT, DNAT/twice
NAT and no-translation tuple derivation, optional counters/state, endian handling,
malformed attributes, recursion/count bounds, peer/sequence/multipart/truncation,
ENOENT/error ACKs, duplicate records, cancellation and concurrent independent
dumps. No privileged execution is performed by these tests. Unsupported platforms
return `ANDEIVA_ROUTED_FLOW_PLATFORM_UNSUPPORTED` with no fallback.

After independent review, the orchestrator may launch the trusted binary **inside
the already authorized gateway namespace** with the dependency already prepared:

```bash
/trusted/path/andeiva-flow-lab
```

There are no arguments and no namespace selector. Native qualification must compare
reported original/reply/translated addresses and ports against known isolated
TCP/UDP flows and server-observed peers; test accounting enabled/disabled, empty
dumps, permission/module failures and cancellation. Preserve external host
IPv4/IPv6 routes and nftables invariants. Do not run namespace setup or enable
dependencies on a customer appliance through this tool.

The existing routing runner now has an explicit opt-in for that native proof:

```bash
go test -race ./internal/routedflow ./cmd/andeiva-flow-lab ./cmd/andeiva-routing-lab
go build -trimpath -o /tmp/andeiva-routing-lab ./cmd/andeiva-routing-lab
sudo /tmp/andeiva-routing-lab --run-isolated-lab-with-flows
```

Run only after review and authorized dependency preparation in the disposable
Debian lab. The runner invokes its own fixed `--observe-current-flows` child
inside the owned gateway namespace immediately after existing TCP/UDP SNAT
probes, before policy replacement or cleanup. It rechecks interface bindings and
current semantic policy readback. Child output is limited to 1 MiB and strictly
decoded, including duplicate/unknown field rejection. Both actual TCP 18080 and
UDP 18081 flows must show LAN `198.18.0.2` to WAN `198.19.0.2`, matching reply
tuples, forward source translated to `198.19.0.1`, preserved protocols/service
ports and `source_changed=true`. Inverse tuple consistency is checked; PAT source
ports may legitimately differ. Optional metrics remain absent when unavailable.
The validated actual snapshot is printed only to the private unit's stdout as
`FLOW_OBSERVATION`. No extra module/sysctl/helper path is introduced. The existing
`--run-isolated-lab` never calls the observer and still works with the component
absent. The integrated native run is qualified separately below.

Rollback is stopping/removing only the staged binary; closing its socket releases
all collector resources. It creates no network objects or persistent runtime.
Docker/EKS/runtime configuration changes: none. Security impact is read-only,
bounded sensitive observation; appliance CPU/RSS and native resource measurements
remain pending. No production resource or inspection claims are made.

Protocol references: [Linux conntrack netlink specification](https://docs.kernel.org/netlink/specs/conntrack.html),
[Linux 6.12 conntrack netlink implementation](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_conntrack_netlink.c).
This code is independently implemented; no upstream GPL implementation is vendored.

Source evidence: Windows unit/stub tests and Linux/WSL offline race tests, vet,
both ten-second fuzz targets, Linux amd64/arm64 and unsupported Windows/Darwin
cross-builds pass. Initial fuzz runs exercised 478282 multipart and 414545
attribute inputs without failure. A synthetic TCP record decoder microbenchmark
on an i7-1370P under WSL measured 6526 ns/op, 10416 B/op and 62 allocations; it
does not measure live dump CPU/RSS, packet latency or appliance capacity. Gosec
reports zero findings without suppressions; Gitleaks and repository source policy
pass. No native conntrack socket was opened by these source checks.

Translations: [Español](docs/es.md), [Português](docs/pt.md).

Native Debian 13 AMD64 qualification passed with the integrated runner in three
isolated namespaces. Actual TCP and UDP conntrack records contained original,
reply and derived translated tuples consistent with the observed SNAT peer.
Unavailable packet/byte counters remained absent. Existing related-ICMP,
IPv6-deny, unsolicited-reverse-deny, established-flow revocation, no-NAT routing
and NAT-without-authorization checks also passed. External host IPv4/IPv6 routes,
nftables and forwarding settings were identical before/after; namespaces were
removed. The locally installed conntrack-netlink module was prepared explicitly
outside the collector and its newly loaded leaf module was removed afterwards.
Combined runner elapsed 3.853 s, CPU 0.395 s, cgroup peak 30,924,800 bytes (including
cache); these are not collector-only RSS, production throughput or appliance
capacity measurements. No administrative API or live-appliance route is enabled.

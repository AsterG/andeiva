# Firewall administration laboratory — FW-ADMIN-001

Experimental authenticated Web/CLI/API flow for a disposable Debian 13 laboratory.
It connects the shared transaction coordinator to a narrowly scoped privileged
helper and an isolated nftables dataplane. It is not an appliance installation,
production authentication, mandatory inspection or a released firewall product.

Operator guides: [English](docs/en.md), [Español](docs/es.md),
[Português](docs/pt.md). They describe the current commands and the same acceptance
procedure. [Validation results and limitations](VALIDATION.md) distinguish real
Debian traffic, browser fixtures, failure injection and resource observations.

| Component | Responsibility |
|---|---|
| `cmd/andeiva-admin-lab` | Provisioning, disposable namespaces, bounded supervisor, HTTPS process and isolated helper |
| `internal/adminauth`, `internal/adminapi` | Random laboratory credentials, sessions, RBAC, CSRF, audit and typed HTTPS contract |
| `internal/adminclient`, `internal/cli` | Explicit CA validation and authenticated official CLI |
| `internal/firewalladmin`, `internal/configpoc` | Candidate/Running/Startup, generation checks, idempotency, confirmed commit and recovery |
| `internal/firewallipc`, `internal/nftguardian` | Bound local channel and independent confirmation deadline |
| `internal/firewallnft`, `internal/nftengine` | Ordered IPv4 policy, stateful responses, exact semantic readback and bounded counters |
| `frontend/src/firewall` | Authenticated `/firewall` UI in EN/ES/PT, light default and explicit dark choice |

The API process has no network administration capabilities. The helper has only
`CAP_NET_ADMIN` inside the disposable gateway namespace. The HTTP contract never
accepts a command, executable, table name, namespace or raw nftables program.
The host network remains outside the managed policy; host snapshots and the
fixture sentinel detect unexpected changes.

Each original packet must match the current ordered policy. Return traffic must
also match its reversed tuple and interfaces, established/reply conntrack state
and an admission mark previously set by an accepted original packet. A deleted,
narrowed or earlier denied permission blocks matching return traffic. A current
allow for the same tuple intentionally permits an already admitted connection.
An admission mark is neither identity nor a substitute for current policy.
Unknown protocols and IPv6 have no allow rules. This lab does not implement
IDS/IPS, AV, WAF, DNS filtering, TLS inspection, NAT or VPN, and supplies no
production exception to mandatory identification or inspection.

The public effective state contains revision identity, verification state and
per-rule packet/byte totals, not raw platform diagnostics. Counters include both
directions and reset on atomic replacement; they are not per-flow logs. The
privileged helper's internal JSON is not an administrative API response.

Rollback uses a journaled canonical revision and verified atomic table replacement.
A normal API restart resumes Running with `Boot:false`; a complete laboratory
start selects Startup with `Boot:true`. Pending or ambiguous transitions undergo
conservative recovery. Killing the helper closes the entire disposable lab;
there is no claim of a functioning dataplane after that failure.

Build/test entry points are listed in each language guide. The experiment adds no
service unit, Docker runtime deployment, EKS workload or Helm configuration. CI
compilation and mock browser tests do not replace an authorized native VM run.

# Transactional configuration experiment

This package explores configuration transactions using simulated components. It is
not connected to the appliance API, frontend, official CLI or traffic engines.
It does not change nftables, routes, interfaces or proxy settings. The prototype
file store is an experiment, not a selection of the production database.

Developer guides: [English](docs/en.md), [Español](docs/es.md),
[Português](docs/pt.md).

## State and revision contract

| State | Meaning |
| --- | --- |
| Candidate | A proposed configuration, owned by its editor and based on the current transaction generation |
| Running | The revision acknowledged and observed on every simulated component |
| Startup | The revision explicitly saved for the next boot |
| Last good | A previously accepted revision available for compensation or recovery |
| Pending | A provisional commit awaiting confirmation, with a rollback target and bounded deadline |
| Recovery required | Effective state cannot be certified; ordinary mutations are rejected until recovery succeeds |

Schema version 1 has a fixed `deny` default and at most 64 ordered rules, each with
an identifier and an `allow` or `deny` action. It has no address, protocol, secret,
security-profile or real packet-matching implementation.
Rule order is semantic: reordering rules must change the revision. Canonical
serialization and its SHA-256 digest identify configuration content. Transaction
generation is a separate concurrency token; an unchanged content hash does not
permit replaying a stale write.

Node identity is deliberately absent from this schema; node-local configuration
mutation is not implemented. Equal shared hashes do not prove
that two nodes have applied the same state, have compatible engines or can fail
over safely. No replication, fencing, quorum or HA runtime is implemented.

## Mutation boundary

Every operation enters the same service with a trusted principal, a transport
label and a typed request. The principal is supplied by the local test harness;
the transport label is audit context, never proof of identity or authorization.
Web, CLI and API labels exercise equivalent service contracts and permissions.
They do not provide working browser management, an HTTP authentication protocol,
JWT validation, SSH identity, CSRF protection or production transport adapters.

The prototype roles are not the finished product's administrator model:

| Role | Service permission |
| --- | --- |
| `viewer` | Read status |
| `operator` | Read status and perform configuration operations; no revocation or audit-history access |
| `admin` | Configuration operations, principal revocation and audit-history access |

A revoked principal is denied regardless of its role. Candidate ownership and
confirmation ownership impose additional checks; a role alone does not transfer
another editor's pending transaction.

Mutation requests carry an expected generation and an idempotency key. Reuse must
be bound to the same actor, operation and payload, not merely the same key text.
Validation must precede component changes. An unauthorized actor, stale proposal,
invalid schema or inconsistent retry must not change effective configuration.

## Commit and recovery

A commit persists its intent before changing a component. Component application
is coordinated and compensating; it is not one atomic transaction across several
engines. Running advances only after all required acknowledgments and effective
state checks. Rollback must cover every attempted component, including a component
that changed state before returning an error.

Commit confirmed applies provisionally. Confirmation closes that window without
saving Startup. Expiry rolls back automatically. Save is explicit and must reject
a pending confirmed commit. Process recovery with a pending confirmation takes a
conservative rollback path rather than granting a fresh confirmation window.
The timer runs in this controller; no independent watchdog or engine-enforced
lease is provided. Recovery after a controller outage is not proof that a real
dataplane would enforce the confirmation deadline while that controller is down.

Reopening the process and booting the appliance are different events. Process
recovery reconciles the durable transaction state. An explicit boot selects
Startup; an ordinary process restart must not silently discard a confirmed,
unsaved Running revision. Neither path may clear protected audit or revocation
state merely because Startup is older.
Prototype revocation restricts future calls by that service principal. It does
not revoke an actual VPN peer, browser session or external identity-provider token.

If compensation, effective-state observation or durable recording fails, the
service must report recovery required rather than declare a successful commit.
An uncertain result must be reconciled before further changes are accepted.

## Persistence and trust limits

The Linux file store uses one writer lock and numbered records containing state
and audit information. A new record is written privately, synchronized, renamed
and followed by a directory synchronization. Acknowledging a mutation before this
sequence completes would make the acknowledgment stronger than the evidence.
Interrupted or ambiguous writes require recovery, not a claim that nothing happened.

The distinction between file and directory synchronization follows the
[Linux fsync contract](https://man7.org/linux/man-pages/man2/fsync.2.html).
[Go File.Sync](https://pkg.go.dev/os#File.Sync) supplies the file operation;
[flock](https://man7.org/linux/man-pages/man2/flock.2.html) is advisory and only
coordinates cooperating processes. A local process able to bypass the store's
ownership boundary is outside that lock guarantee.

Records are bounded by record count, a 1 MiB individual record limit and a 64 MiB
journal limit. Reaching the prototype capacity rejects further changes;
protected history is not rotated away to make a test pass. Checksums and hash
links detect certain accidental changes. They do not authenticate a publisher,
prevent a local writer from rewriting history or detect every rollback of an
entire store without an external trusted anchor.

Tests that reopen files or terminate a process do not prove resistance to power
loss. Storage hardware caches, filesystems, controller failures, physical media
damage and real appliance backup/restore require separate evidence. There is no
encryption, signed update chain or production retention policy in this prototype.

## Acceptance matrix

These are executable-test requirements, not a statement that a particular run
passed. Record the actual source revision, environment, exit code and limitations.

| Area | Required observation |
| --- | --- |
| Canonical model | Stable hashes for identical content; semantic rule-order changes produce a different hash; unsupported schema rejected |
| State separation | Stage does not alter Running; commit does not save Startup; save persists the chosen Running revision |
| Confirmed commit | Explicit confirmation succeeds once; timeout and pending restart compensate; save cannot bypass confirmation |
| Concurrency/retry | Conflicting writers cannot silently overwrite; exact retry is stable; changed retry payload is rejected |
| Authorization | Unauthorized and revoked principals cannot mutate; Web/CLI/API labels yield equivalent decisions |
| Engine failures | Failures before and after mutation, wrong acknowledgment and drift cannot publish an unverified Running state |
| Store failures | Intent/audit failure prevents apply; interrupted writes and capacity exhaustion fail safely |
| Recovery | Partial apply, failed rollback and restart reconcile or remain explicitly blocked; explicit boot uses Startup |
| Audit | Accepted changes and outcomes remain attributable; configuration save does not erase history or revocations |
| Resources | Report operation latency, allocations, CPU/RAM and disk for the measured workload; do not extrapolate to packet processing |

The complete configuration release gate additionally requires real components,
traffic observation during failures, database selection and durability testing,
production authentication, backup/restore and a defined resource envelope. A
green simulated-engine suite alone does not close that gate.

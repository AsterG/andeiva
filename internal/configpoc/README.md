# Transactional configuration experiment

This package implements the coordinator reused by the experimental administration
runtime. Its standalone tests use simulated components; runtime adapters supply
the real engines. The coordinator itself issues no nftables, route, interface or
proxy commands. The prototype file store is an experiment, not a selection of
the production database.

Developer guides: [English](docs/en.md), [Español](docs/es.md),
[Português](docs/pt.md).

## Journal reading and capacity

The store validates the complete committed chain at open, retaining lightweight
record metadata, validated audit and the latest durable state rather than every
historical state. Audit queries retain the previous behavior: copies of audit
validated at open/append, without rereading all configuration records. They do not
promise immediate detection of later disk tampering. Historical configuration
queries read bounded records on demand and
verify identity, ownership, permissions, size, sequence, predecessor and hash.
A missing or changed record is a storage error, not an absent rollback target or
permission to execute a previously seen request again. Queries return no partial
configuration page after a verification error. This does not provide protection against a
privileged attacker rewriting all trusted storage.

An integrity error discovered during a historical read blocks new administrative
mutations, including Confirm and Recover, and reports recovery required. It does
not repair files or cancel an existing pending timeout: automatic safety rollback
retains its existing journal/reservation requirements. A complete valid reopen is
required before ordinary writes resume. Do not delete records or reset the store
to clear this condition. This is distinct from a physical full-volume recovery broker.

The v1 disk format, hashes and full current receipt map are unchanged. Exact retry
still checks authorization and actor/body binding, then returns the current
Snapshot with the original ReplayedGeneration before checking a new generation.
Reading history does not expire receipts or migrate files. A legacy compatible
binary can read the same unchanged journal; ordinary service open/resume still
performs its existing durable recovery writes.

This reduces retained historical state in RAM. It does not remove the full-chain
startup scan, add checkpoints or compaction, increase capacity or implement disk
quotas. The 1,024 receipts, default 2,048 records, 64 MiB journal and 1 MiB record
limits remain. AND01, protected-audit exhaustion and continuity with a full volume
remain separate release blockers. No 5,000-cycle or power-loss claim is made.
Legacy audit strings have no separate per-field byte cap; measured memory for a
fixture is not a universal heap bound. Total journal limits still apply.
See [measured observations and reproduction](READ_VALIDATION.md), including the
additional cost of verified revision reads and the unchanged capacity limitations.

## State and revision contract

| State | Meaning |
| --- | --- |
| Candidate | A proposed configuration, owned by its editor and based on the current transaction generation |
| Running | The revision acknowledged and observed on every configured component |
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

Node identity is deliberately absent from schemas 1/2; node-local configuration
mutation is not implemented. Equal shared hashes do not prove
that two nodes have applied the same state, have compatible engines or can fail
over safely. No replication, fencing, quorum or HA runtime is implemented.

Schema 3 adds `local_services`, a canonical `localpolicy.Config`, while retaining
the existing forwarding fields and schema-2 match validation. Schemas 1/2 reject
that field and retain their exact serialized bytes, revision hashes and request
fingerprints. Opening an existing journal never migrates it; migration is an
explicit staged transaction. Legacy revisions contain no managed local services.
The local inventory remains part of this bounded experiment, not an HA model.

Changing local declarations requires a confirmation window, including migration
from a legacy revision. Historical rollback involving schema 3 also requires a
window, even when its local declarations are unchanged. Legacy-only rollback
remains immediate. Managed windows are 30–120 seconds; the unguarded experiment
permits 20 milliseconds–5 minutes for fault tests. Pending rollback retains the
previous Running revision as its expiry/restart target and cannot be saved before
confirmation. These core contracts do not implement listeners or kernel policy.

## Mutation boundary

Every operation enters the same service with a trusted principal, a transport
label and a typed request. The principal is supplied by a trusted runtime adapter
or local test harness;
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
If applying Startup fails, compensation targets the last confirmed recovery
anchor, not the failed Startup revision or an unconfirmed Running revision.
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
The selected parent and all its ancestors must remain trusted. Path checks reject
symlinks and noncanonical paths; they do not protect against another process
replacing an ancestor concurrently.
Journal and staging operations use relative paths through the same scoped
`os.Root` handle after acquisition and directory identity validation.

Records are bounded by record count, a 1 MiB individual record limit and a 64 MiB
journal limit. Reaching the prototype capacity rejects further changes;
protected history is not rotated away to make a test pass. Checksums and hash
links detect certain accidental changes. They do not authenticate a publisher,
prevent a local writer from rewriting history or detect every rollback of an
entire store without an external trusted anchor.
Staging uses a project-owned format, independent of Go's temporary-file naming.
The store root contains `staging-v1.owner`; the private `.andeiva-stage-v1/`
directory contains matching `owner.json` metadata and, while writing, one fixed
`record.tmp` payload of at most 1 MiB, separate from the committed journal budget.
Both metadata files contain identical canonical JSON, at most 256 bytes, with
`format` set to `andeiva.config.staging.v1` and the same randomly assigned
`store_id` of 32 lowercase hexadecimal characters. Directories
must be owned by the current user with mode `0700`; metadata and payload files
must be owned, single-link regular files with mode `0600`.

Under the exclusive writer lock, reopening validates the entire committed chain,
all directory entries and the ownership metadata before removing an orphan
`record.tmp`. The payload may be incomplete; its registered location and validated
metadata establish cleanup eligibility, not its JSON contents or filename suffix.
No other file is eligible. Unexpected entries, foreign or mismatched metadata,
and legacy `.pending-*` files block opening and remain available for investigation.
Committed records are never deleted by this cleanup.

A fully validated older journal without either ownership marker or staging
directory can initialize this format. Partial initialization, such as a lone
marker or missing inner metadata, blocks opening and requires investigation;
it is not automatically repaired or deleted. Preserve the original directory and
failure output. Do not edit ownership markers, rename unknown files into the staging
namespace or delete files to force reopening. These markers are not authentication
against a process using the same UID or root; both are outside this trust boundary.
The journal stores complete snapshots and receipts, so its disk limit is not a
RAM or transaction-throughput budget for a production database.

Tests that reopen files or terminate a process do not prove resistance to power
loss. Storage hardware caches, filesystems, controller failures, physical media
damage and real appliance backup/restore require separate evidence. There is no
encryption, signed update chain or production retention policy in this prototype.
Subprocess interruption tests use real processes and files, but recreate simulated
engines on recovery; they do not demonstrate an independent dataplane surviving
the controller process.

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
| Staging recovery | Only the registered bounded payload is cleaned after complete validation; unexpected entries, legacy temporaries and partial ownership initialization are preserved and block opening |
| Recovery | Partial apply, failed rollback and restart reconcile or remain explicitly blocked; explicit boot uses Startup |
| Audit | Accepted changes and outcomes remain attributable; configuration save does not erase history or revocations |
| Resources | Report operation latency, allocations, CPU/RAM and disk for the measured workload; do not extrapolate to packet processing |

The complete configuration release gate additionally requires real components,
traffic observation during failures, database selection and durability testing,
production authentication, backup/restore and a defined resource envelope. A
green simulated-engine suite alone does not close that gate.

## Bounded transaction capacity (AND01: partial)

Ordinary mutation admission also observes available filesystem bytes and inodes
through an owned-directory descriptor on Linux. The budget includes the existing
maximum record size, the operation's logical reserve, and staging metadata. Unknown
metrics, a read-only filesystem or insufficient space return `ErrStorage` before
activation authority or engine effects. Rejected-request audit uses the same
ordinary headroom check. Transient pressure does not mark the journal corrupt,
halt the service or cancel an outstanding confirmation timer; authorized reads
and exact replay remain available.

The four-block metadata allowance is exercised by the finite tmpfs tests; it is
not a universal metadata bound for every filesystem. This observation does not
allocate a physical reserve or enforce a filesystem quota. Other writers can
consume space after admission, and per-identity quotas
may fail despite free filesystem space. Actual write/fsync failures retain the
existing compensation and recovery behavior. Required recovery and autonomous
confirmation expiry retain their critical persistence path; a read-only or full
filesystem may still prevent its durable outcome. No permanent forwarding or
unlimited-write guarantee follows from this check.

`TestStorageSpace*` covers deterministic admission and recovery behavior with
simulated engines. `TestRealStoragePressure` is opt-in and requires the isolated,
bounded tmpfs laboratory harness; normal tests skip it. It exercises real byte
and inode exhaustion, read-only rejection, capacity release and reopen recovery.
The read-only mode verifies the probe and an actual `EROFS`, not service bootstrap.
None of these tests modifies host network rules.

Confirmed commit and confirmed historical rollback require capacity for their two
records, resolution (up to two records), and one subsequent recovery/reopen (two
records) before activation. Pending transactions retain four records against
ordinary writes and rejected-request audit floods. Confirmation uses its own
admission threshold; unauthorized, stale or malformed requests cannot spend the
reserve. One receipt is retained for required recovery, and pending admission
also retains a confirmation receipt. Healthy repeated recovery cannot bypass
these limits. Byte admission budgets the existing 1 MiB maximum per record,
including future receipt and state growth; no journal format or hash changes.

The 64 MiB journal, configured record limit (default 2,048), and 1,024 durable
receipts remain lifetime bounds. Ordinary writes may therefore stop earlier.
Audit that cannot be persisted returns a storage error; it does not consume the
reserve or report successful auditing. At quota, authenticated status/history and
exact replay remain available in an otherwise healthy open service. Existing
exhausted journals are not repaired: reopening requires room for both intent and
outcome and leaves the files unchanged if that capacity is absent on a healthy
resume. Repeated restarts or physical I/O failures can still block operation.

AND01 is **partially addressed**, not a complete storage-lifecycle solution.
Compaction, retention, receipt lifetime and key-management policy require a
separate reviewed ADR; this change neither deletes records nor increases quotas.
The tests use simulated engines and bounded quota accounting, not a full-disk or
Debian appliance benchmark. Native resource and physical-failure gates remain open.

## Journal publication conflicts

Linux journal append uses `renameat2(RENAME_NOREPLACE)` with verified source and
destination directory descriptors. A competing destination is not overwritten;
unsupported operations fail closed. Failed publication may remove its own staging
payload only while its recorded identity still matches. A substituted payload is
not removed by that failed append. Reopening retains the existing ownership rules
for registered staging names; this is not isolation from an arbitrary same-UID or
root writer. Unexpected records fail validation instead of being silently deleted.
Formats, receipt replay, protected history and capacity limits are unchanged.

Reproduce with `go test -race ./internal/configpoc -run '^TestJournal'`, then run
`go test -race ./cmd/... ./internal/...` and `go vet ./cmd/... ./internal/...`.
Process-exit recovery tests do not establish physical power-loss resilience.

### ES

La publicación del journal no reemplaza destinos existentes y rechaza sistemas sin
soporte atómico. Una escritura fallida solo puede retirar su temporal si conserva
la identidad registrada; no elimina un payload sustituido. La reapertura conserva
el contrato de propiedad de temporales registrados: no aísla de un escritor con
el mismo UID o root. Los formatos, reintentos y límites no cambian. Las pruebas de
salida de procesos no demuestran resistencia a cortes eléctricos.

### PT

A publicação do journal não substitui destinos existentes e recusa sistemas sem
suporte atômico. Uma gravação com falha só pode remover seu temporário se mantiver
a identidade registrada; não remove um payload substituído. A reabertura mantém o
contrato de propriedade dos temporários registrados: não isola um escritor com o
mesmo UID ou root. Formatos, reenvios e limites permanecem iguais. Testes de saída
de processos não comprovam resistência a cortes de energia.

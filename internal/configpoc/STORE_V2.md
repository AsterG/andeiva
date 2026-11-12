# Offline configuration storage v2 foundations

This internal implementation prepares storage and operation catalogue slices
A–C. It is not connected to Service, HTTP, CLI, Web, helpers or engines. Its
selected state is explicitly non-operational. Existing v1 installations and
their receipt limits are unchanged. AND-01 and persistent AND-02 remain open.

## Persistence

An owned 0700 directory is separate from both legacy domains. Files are owned,
single-link regular 0600 entries. Scoped descriptors and existing pinned-read,
strict-canonical JSON, ownership, lock and synchronization helpers are reused.
Read-only preflight rejects foreign layouts before lock creation; authoritative
byte/inode accounting and recovery flags are rescanned after acquiring the store
lock. Initialization also rechecks an empty workspace under that lock, so another
initializer's newly selected state cannot be replaced.
Content-addressed immutable objects use generated SHA-256 names and exclusive
creation: collisions are verified byte-for-byte, never replaced. Hashes provide
integrity, not authentication against an attacker controlling the same UID/root
and all persistent storage.

`selected.json` atomically selects current and previous immutable selections.
Each selection references its metadata snapshot and predecessor. Delta segments
have at most 64 links; a checkpoint resets the active validation segment without
deleting protected older selections. The prior complete selection remains
readable. Write/sync/publication ambiguity fences further writes. Reopening
reconciles the selected complete state. A leftover `selection.pending` is retained
and fences writes; it is not guessed to be safe for cleanup. Source layouts and
unselected immutable objects are never automatically removed.

Operations use a fixed-depth radix index: three pages of 64 hashes and one bounded
operation record per exact lookup. There is no catalogue-sized in-memory map or
unbounded cache. A mutation publishes three small index pages rather than dumping
the whole catalogue. Metadata contains bounded subject/namespace registries.
At most 256 subject records and 256 namespaces are hot/retained registry entries.
Closed namespaces can leave that registry only after their window and every owned
operation's retention/pinning obligations have resolved through explicit logical
retirement. A retired subject with no namespaces can leave the hot registry;
legacy bindings pin their subject records. Immutable historical registry images
remain protected. Namespace/subject issuance counters never rewind; missing old
handles never recreate an identity or namespace. Reclamation scans are bounded by
the configured live operation capacity and do not load the catalogue into RAM.

The index capacity is **live slots**, not the issuance lifetime. The monotonic
operation sequence selects a circular slot. A slot can be reused only after its
previous exact operation is terminal, explicitly retired after the promised
retention window, and unpinned. Exact ID, sequence, lineage, namespace and subject
checks prevent a reused slot from becoming authority for an old or forged handle.
When exact retired metadata is no longer current, lookup returns not-found rather
than asserting that an unknown ID was once valid. Sequence overflow refuses work.

## Catalogue lifecycle

Namespaces are durably discoverable after a lost response. Admission persists
the immutable request, fingerprint, server-issued ID and accounting reservation;
it executes nothing. Begin checks ownership, namespace, deadline and global
generation, and persists pending before any future coordinator could execute.
Another pending or uncertain operation blocks a conflicting begin. Final retries
return the historical outcome, separately from the store's current state.

Finish persists an internal caller-verified outcome and its audit object in the
same selected state. This is a persistence primitive, **not proof that an engine
applied a rule**. Slice D must supply verified effects/readback and authoritative
state/projection changes; this implementation cannot activate operational Running.

Accepted expiry/namespace closure finalizes without effects. Pending, uncertain
and confirmation-pinned operations keep their reservations. Reads never extend
retention. Backward time refuses expiry/new mutations; no monotonic-time trust or
physical clock qualification is claimed. Thirty days is the internal fixture
retention policy, not an advertised appliance guarantee.

Bytes and inodes are admission accounting budgets. Conservative lifecycle
16 MiB / 64-inode allowances protect other admitted operations from ordinary
metadata allocation; each pending operation may consume its own allowance only.
They are **not filesystem quotas or physical reserved blocks/inodes**. Real finite
volume ENOSPC, EDQUOT, inode, read-only and open-deleted-file continuity tests remain
required after coordinator integration.

Retirement changes the current lookup view only. Old detail, protected audit,
legacy backups and old index objects remain on disk. There is no garbage
collection, export/acknowledgement or protected-history deletion. Disk use still
grows until the configured accounting budget refuses new admissions. This
preparation therefore does not close storage exhaustion/retention release gates.

## Cold migration

`prepareMigrationV2` locks firewall, local-services, then destination, in that
fixed order. It inspects both complete v1 journals directly, never Service.Open,
openStore/load or engine methods. Registered incomplete staging, unresolved
Candidate/Intent/Pending/recovery, malformed histories or ambiguous actor mappings
are refused without source mutation or cleanup.
Distinct domains must also have distinct persisted source identities; cloned
ownership registrations are refused before writing the destination.

Original schema 4/3 payloads, revisions, distinct Startup, generations, receipt
fingerprints/original receipt generations and all original protected journal bytes
are retained. Explicit source/actor/receipt-index-to-subject bindings prevent
ownership being inferred from a reused username. A fresh global lineage starts
at generation 1; original domain projection seeds remain explicit provenance.
The prepared composite is published with a single initial storage selection at
sequence 1. Interrupted import leaves no selected empty placeholder and retains
the complete original v1 layouts for their authorized recovery path.
Credential rotation/authorized rename retains a subject; retirement and creation
of the same login allocate a different incarnation and preserve the tombstone.
Subject retirement closes its namespaces in the same selection, without inventing
terminal outcomes for accepted work or releasing in-flight/pinned reservations.
Ordinary expiry may later finalize accepted work without effects. Internal
retirement can then remove eligible old operations/namespaces even though the
subject is inactive; pending recovery still pins its registry record.

The imported schema 5 composite has `network:null`, separate Running targets and
Startup references, and status `prepared_requires_global_readback`. Preparation
does not select global operational Running or restrict still-unmigrated v1 writes.
The internal legacy replay reader returns the imported projection and original
receipt generation only. Slice D must wire current projections, cutover, the real
old-binary downgrade guard and global readback; E must implement explicit v1
replay-only opt-in and coordinated transport/authentication adapters.

## Reproduction and evidence boundaries

On Linux with the repository's approved Go toolchain/cache:

```sh
go test ./internal/configpoc -run '^TestV2' -count=1 -timeout 25m
go test -race ./internal/configpoc -run '^TestV2' -count=1 -timeout 10m
ANDEIVA_CONFIG_V2_ENDURANCE=1 go test -race ./internal/configpoc -run '^TestV2DurableCatalogue5000Lifecycles$' -count=1 -v -timeout 35m
go vet ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
go test ./internal/configpoc -run '^$' -bench BenchmarkV2CatalogueLifecycle -benchtime=10x -benchmem
```

The explicit endurance command qualifies 5000 **catalogue** admit/begin/final
lifecycles. General test commands visibly skip that dedicated endurance test;
a skipped endurance test is not a successful endurance qualification. Tests use cold exact
lookup, and 320 monotonic lifecycles across a 64-live-slot fixture with explicit
retirement and protected retained slots. A four-namespace/two-subject fixture also
crosses its live limits through 20 issued lifecycles without reviving old handles.
These are not 5000 actual
stage/validate/commit/confirm/save/rollback coordinator cycles. Process exits and
fault hooks qualify the tested filesystem protocol, not resistance to power loss.
Multiplatform compilation does not imply supported non-Linux durability/runtime.

Localized guides: [Spanish](STORE_V2_ES.md), [Portuguese](STORE_V2_PT.md).

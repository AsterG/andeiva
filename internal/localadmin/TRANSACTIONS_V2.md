# Prepared Local Services v2 transactions

[Español](TRANSACTIONS_V2_ES.md) · [Português](TRANSACTIONS_V2_PT.md)

This integrates the prepared proof mapper/book with the existing single v2
configuration coordinator. It does not activate HTTP/SSH routes, advertised
capabilities, deployed helpers, host rules, listeners or network interfaces.
Firewall remains schema 4; Local Services remains schema 3; the composite remains
schema 5. No second configuration database or transaction engine is created.

## Administrative contract

`OpenServiceV2WithLocalPolicy` accepts a trusted constructor-owned policy bound
to the same authentication Manager. The ordinary constructor has no policy and
continues rejecting local writes. `PreparedBridgeV2` pins receiver metadata from
listener assembly; request bodies cannot select a receiver or supply a scope.
There is no new public wire contract in this slice.

Fresh session verification finishes before the configuration lock. Under that
same lock the coordinator rechecks the canonical subject, login and credential
revision, admitted operation, namespace, global CAS and domain projection.
The resolver derives the target, fingerprint, revision generations and exact
pending origin/lease/deadline. Rollback additionally requires a retained verified
composite witness whose firewall component equals the current firewall.

Stage and Validate require no connectivity tokens and reject irrelevant evidence.
Commit requires 30–120 seconds of confirmation; immediate local Commit is denied.
Rollback uses a fixed 30-second confirmation window without changing its request
DTO. Commit, Rollback and Save require a recovery proof. Confirm requires that
proof plus one proof from every enabled target binding; all-disabled targets
require recovery only. Save is prohibited while confirmation is pending.

The complete evidence set is reserved atomically before durable intent or engine
effects. A provable pre-admission failure releases it; selected or uncertain
intent publication consumes it. Final replay needs fresh authentication but
neither old tokens nor repeated effects. Recovery tokens remain tied to the exact
session; managed endpoint proofs may use another current session of the same
durable subject/credential incarnation. TTLs remain 20/60 seconds, capped by the
operation window and confirmation deadline. Tokens/handles are ephemeral and
excluded from configuration, audit and ordinary serialization.

## Application and recovery

Candidate, Running and Startup remain independent per domain. A local operation
preserves the other domain's candidate and configuration. Domain and global
generations are distinct; only one global activation/confirmation is pending.
Both domains must pass effective readback before a result is selected. Guard
operations use the chosen domain and original lease deadline. Autonomous timeout
and restart compensation require durable intent and exact authority readback,
not a current user session or reused proof. Origin outcomes stay immutable while
pins, recovery audit and current selection change atomically.

Stage/Validate/Save never apply a component to repair external drift between
readbacks. Such drift is fenced; it cannot make a local metadata operation write
firewall policy or publish an unverified Running revision. An admitted local
operation uses a detached, bounded context so retiring its own connection cannot
cancel an already admitted helper exchange; earlier caller deadlines still bound it.

Pending listener proof publication follows verified readback and durable pending
selection. It uses a dedicated pending view, not an invented Confirm operation.
The in-memory listener-factory registry must supply actual receiver instances;
its callback must not call auth, coordinator, engines, disk or network under the
configuration lock. Instance replacement invalidates prior endpoint evidence.

Before the first selected local intent, the store adds sticky required feature
`local_services_transactions.v1`, alongside `boot_startup.v1` when applicable.
Readers must understand it before processing local state; default old-state
encoding is unchanged. A private qualification compiled the actual reader source
from commit 9e59f35: it accepted the default control store with no Apply and rejected
the local feature after 216 selections before engine calls. This is not a downgrade
or cutover authorization, nor permission to strip feature history.

## Reproduction and limits

With Go 1.27.4 and dependencies available offline on Linux/WSL:

```sh
GOPROXY=off GOSUMDB=off go test -race -buildvcs=false ./internal/configpoc ./internal/localadmin -run 'TestCoordinatorLocalV2|TestLocalTransactionsV2' -count=3 -timeout=5m
go test -race ./internal/configpoc ./internal/localadmin -count=1 -timeout=12m
go vet ./internal/configpoc ./internal/localadmin
go build ./cmd/... ./internal/...
```

The Local Services integration tests use real journals, authentication, proof
book and in-process guardian with simulated component engines. Coordinator fault
tests explicitly simulate the evidence authority and persist simulated component
hashes across actual process exits at intent/apply/readback boundaries. These are
different evidence scopes; neither demonstrates kernel rules or actual listeners.

Actual helper/listener qualification, HTTP/SSH
receiver handoff and Web/CLI/API cutover remain separate gates. OS boot with a
different local Running/Startup still fails explicitly before effects; domain-safe
local Startup activation is a required follow-up, not a completed reboot feature.
Physical reserve/GC integration, protected export authority, AND-01/02 and full
appliance resilience are not completed here. No production capacity claim is made.

Before activation, rollback removes unused prepared code. A selected feature store
must retain compatible readers and protected history; never reactivate live v1
writers or reuse proof tokens to work around a failed recovery.

Native qualification on Debian 13 ran the exact test binaries as UID 1000 with
no-new-privileges and isolated networking: combined process elapsed 3.561436 s,
CPU 1.598901 s and cgroup memory peak 21,815,296 bytes. This includes real journals,
authentication/proof-book paths and simulated engines; it is not a real helper or
listener activation, throughput benchmark or appliance-wide resource guarantee.

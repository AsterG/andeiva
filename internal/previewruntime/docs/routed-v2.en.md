# Routed configuration authority

The V2 control plane can consume an exclusive routed authority supplied by the
trusted supervisor. Administrative input cannot select a namespace, pool,
artifact path, helper identity or activation capability. Firewall schema 6 and
local service schema 3 form one schema 7 candidate and one guarded transaction.

Before arming, the coordinator selects typed, content-addressed ownership,
dependency and scope records with its existing intent and recovery reservations.
The helper checks that exact plan and its original deadline, applies compiled
batches, and reads the effective state. Confirmation uses the original commit
operation and target revision exposed by the selected Pending record. Save
copies the complete confirmed Running configuration into Startup.

The helper outlives an API/catalogue close. Reopening the controller preserves
confirmed state; unresolved confirmed commits follow the existing restart
compensation contract. A new helper or boot must not adopt the old namespace
identity or manufacture a fresh confirmation lease.

`TestRoutedPhysicalCoordinatorConfirmedLifecycle` exercises real configuration
objects, authentication, reserve files, compilers, semantic readback and guardian
leases with simulated kernel/network transports. It does not establish real
packet forwarding or boot acceptance. A further scenario replaces the helper
instance within the same authenticated namespace incarnation: confirmed state
is retained, and an orderly stop of a pending helper is reconciled through a
selected recovery intent. A foreign run identity is refused before effects.
This does not simulate abrupt power loss. Group boot and the
production IPC assembly require their complete integration tests.
The V2 router currently refuses V1 mutation routes; known migrated V1 replay
dispatch still requires integration and is not claimed as available here.

Run in Linux: `go test -race ./internal/configpoc ./internal/previewruntime
./internal/localnft ./internal/routedactivation`. Test resource consumption is
pending measurement; it is not appliance capacity evidence.

The Startup6 fixture now starts a fresh, authenticated namespace incarnation
with all three managed tables absent. A read-only preparation captures that
actual baseline. The selected boot intent and system reservation precede all
effects; its deadline is exactly the original recovery record time plus ten
seconds. Only verified, confirmed readback publishes the new active ownership.
Two imported schema4 rules and their saved revision remain retained. The
separate prospective boot baseline is applied only by a later explicit rollback,
and is never described as the physical pre-boot ruleset. Candidate data is
preserved without silently rebasing it when Startup changes Running.

This test uses simulated kernel/network transports. Initial Startup4 without an
L3 plan remains refused until the explicit no-network boot profile is integrated;
no default network plan is fabricated to bypass that boundary.

The no-network artifact profile now distinguishes observed links from a desired
network plan. Its feature-gated schema4 candidate captures both policy domains;
the group owner rejects independent firewall/local-service writes. Core boot
validation requires the saved revision's protected witness, an exact observed
baseline and a separately identified prospective legacy policy. These checks do
not implement the physical no-network adapter or activate an installer option.

Owned grouped candidates have explicit `replace_candidate` and
`discard_candidate` operations. Both require the current global generation and
`expected_candidate_stage_operation_id`. Replacement supplies a complete firewall
configuration and preserves the selected local candidate; a local-access change
without its existing proof is refused. Discard removes selected candidates only,
retaining protected audit and historical outcomes. Stage still requires no
candidate. These operations never apply network or firewall changes; their
selected feature marker prevents older readers from silently interpreting them.

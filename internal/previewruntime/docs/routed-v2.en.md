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
packet forwarding, fresh-helper recovery or boot acceptance. Group boot and the
production IPC assembly remain gated until their complete integration tests.
The V2 router currently refuses V1 mutation routes; known migrated V1 replay
dispatch still requires integration and is not claimed as available here.

Run in Linux: `go test -race ./internal/configpoc ./internal/previewruntime
./internal/localnft ./internal/routedactivation`. Test resource consumption is
pending measurement; it is not appliance capacity evidence.

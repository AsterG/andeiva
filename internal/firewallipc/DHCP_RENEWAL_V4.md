# Same-effective DHCP renewal transport

Trusted peers must explicitly negotiate `routed_dhcp_same_effective.v4` in
addition to selected DHCP, inventory and integrity capabilities. Legacy clients
cannot send `dhcp_renew`; the request contains only the selected Work and new
snapshot hashes. The reply carries the authenticated grant or a recovery error.
This transport does not itself validate effective L3 equality or activate renewal.

Only this profile permits ten seconds for apply/open/withdraw/retire/renew RPCs.
Legacy mutations and all ordinary reads retain three seconds. Shorter caller
contexts and cancellation still bound client waiting; a lost reply or timeout
does not prove the helper made no changes or finished compensation. The existing
channel is invalidated on uncertainty. Lease, confirmation and recovery
deadlines are unchanged. No new process, listener, store or dependency is added.

Tests use real in-memory connections and a virtual clock to verify negotiation,
legacy limits, profile limits, shorter callers, cancellation and read limits.
Run `go test -race ./internal/firewallipc` and `go vet ./internal/firewallipc`.
This is transport qualification, not native renewal or appliance performance.

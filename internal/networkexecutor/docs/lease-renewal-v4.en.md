# Operational lease evidence refresh

Same-effective refresh accepts two canonical snapshots with a strictly newer
sequence and identical identity, owner, interface, desired configuration and
complete effective L3 delta. Only sequence, absolute deadline and snapshot hash
may differ. A shorter fresh deadline is valid; no minimum lifetime is fabricated.

Trusted assembly must authenticate selected Work and prove forwarding and gate
closed before calling refresh. The executor checks original ownership, baseline,
fresh current evidence and exact physical state before and after. It replaces
only in-memory evidence; no address, route, selected snapshot or R2 is rewritten.

Only the trusted classified-renewal error permits a verified close followed by
fresh evidence. Ordinary authority failures retain their irreversible fence.
Closed-gate preflight rejects consumed sequences without effects; it does not
grant forwarding authority or clear a fence. Legacy behavior is preserved.

Reproduce with `go test -race ./internal/networkexecutor` and
`go vet ./internal/networkexecutor`. Cases cover immutable deltas, replay,
readback failure, cancellation, ended lifetime, fencing and disposal. No new
process or periodic work is added. This component alone does not enable renewal
or qualify appliance throughput, native traffic or CPU/RAM budgets.

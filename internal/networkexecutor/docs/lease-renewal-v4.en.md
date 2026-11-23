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

An internal `CloseOnExpiryV4` option defaults off. Its BOOTTIME threshold is
sampled before token installation and can only close earlier. At that threshold,
Verify closes the exact table with a bounded lifetime context and proves closure.
It returns `ErrLeaseGateExpired`, retains the consumed sequence and never reopens
that token. A fresh authenticated sequence still passes all normal checks.
Legacy, pre-threshold drift, clock failure and uncertain closure retain fencing.
No lease deadline is extended. Tests include expiry crossing during readback,
replay, a fresh grant and foreign objects. No process, timer or storage is added;
the opt-in path adds clock observations. Appliance resource benchmarking and
runtime integration remain pending.
## Owner changes during the final read

An explicitly classified same-effective renewal can arrive after authority
verification and before a subsequent Current read in Stage, Open or Verify.
Preserve that classification through the read: remove the old permit and prove
the exact closed table, retaining the consumed sequence. It grants no permission
to reuse that sequence. Generic errors, changed authority and uncertain closure
retain permanent fencing. No new process, timer, state format or runtime
activation is introduced; integrated native/resource qualification is separate.

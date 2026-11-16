# DHCP acquisition without a lease

The acquisition service can remain alive after expiry or revocation. Its atomic
observation distinguishes this state from initial waiting, a usable lease and
process/channel failure. No-lease observations carry only a monotonic revocation
epoch and the authenticated acquisition identity. They cannot restore an old
lease, restart the engine, extend a deadline or authorize forwarding.

After the previous selected work is durably retired, `dhcp_begin` may report a
versioned no-effect result. It first proves the original LAN/empty-WAN baseline,
forwarding disabled, gate closed or absent, released selected work and a ready
runtime. A second atomic owner observation validates continued acquisition; if
BOUND has already arrived, the normal grant path uses that observation instead.
Only this pre-effect result preserves existing client qualification. It never
creates qualification; generic errors and cancellation retain their fences.

The service resource view permits only its bounded WAN raw-socket profile while
without a lease, with zero TCP/UDP listeners. Valid lease/R2/epoch/deadline checks
still control all L3 and forwarding effects. Owner death or protocol failure
requires the existing supervised recovery path; no cgroup or PID is adopted.
The existing supervisor and cgroup containment remain unchanged.

Unit tests cover atomic EXPIRE/BOUND, real private pipes and codec/client
qualification, revoked-epoch replay, cancellation, mixed frames and forbidden
listeners. Run `go test -race ./internal/dhcpclient ./internal/firewallipc ./internal/previewruntime -run 'Test(AcquisitionNoLease|RoutedDHCP(NoLease|WaitingV1|InitialWaiting))'`.
Native renewal/reacquisition, installed-unit privileges and resource benchmarks
remain pending. This is a source-level change, not appliance qualification.

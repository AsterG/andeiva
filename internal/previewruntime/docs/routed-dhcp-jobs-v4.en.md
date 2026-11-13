# Selected DHCP owner integration

This opt-in connects the existing grouped runtime, LAN bootstrap, deferred root
producer and selected lease executor. It does not introduce a DHCP engine.
`RoutedLaunchResourcesV3.DHCPJobs` requires integrity; the deployed root assembly
must explicitly select it. Static and NoNetwork plans create no DHCP producer or
reconciliation timer. The existing grouped supervisor retains a private control
socketpair; the API never inherits it.

The helper initially observes NoNetwork. Preparation chooses the static executor
or LAN bootstrap, retaining exactly one namespace writer. Configured networks
keep their exact Desired hash. The same LAN object supplies Authority and DHCP.
No Stage, Prepare, Current or API-ready event starts acquisition.

After a complete `inspect/check`, the trusted helper callback verifies the exact
selected bundle, idle owned policy, LAN readback and independently empty listeners.
It asks root to prepare a deferred producer through inherited FD15. Root reads the
selected source with the capless preflight child, pins producer identity/pidfd,
and transfers exactly three real descriptors. A separate Activate operation
confirms the actual acquisition PID through the producer's private control.

The live publication barrier is `ServiceV2.InspectRuntimeV1`'s existing store mutex,
held across that entire RPC and final revalidation, together with helper controller
ownership. Root does not open or wait for a second checkpoint flock. Before and
after Prepare/Activate, root compares the complete selected reference; mismatch
closes the producer before acknowledgement. The helper revalidates again before
exposing availability. Retirement uses a different barrier: the retained writer
flock after process drainage. A preflight result alone grants neither effect.

The private `dhcp_selected` reply is only a scheduling hint after complete
inspection. Existing R2 checks and original BOOTTIME lease deadlines authorize
every effective change. Reconciliation polls at 500ms only while DHCP is selected;
the existing integrity scheduler pauses reconciliation during inspection without
withdrawing a healthy lease. Failed inspection closes token/forwarding and retains
R2 evidence for verified withdrawal. Request sequence never changes lease epoch.

Rollback requires selected WAN retirement, then stops the producer before LAN
restoration. Existing LeaseGate.Dispose retains a closed gate for supervisor
teardown; this delta does not claim zero residual DHCP rules in a reused scope or
arbitrary reattachment after producer death. It does not implement DHCP server,
change host networking, or prove deployment/native readiness. Native tests must
cover first transition, acquisition, renewal/loss, inspection, API restart,
rollback and namespace drainage. Resource measurements remain pending.

# ADR-074 addendum — Go runtime descriptors in migration workers

The Linux `andeiva-preview` executable sets the Go 1.27 build default
`//go:debug containermaxprocs=0`. This prevents Go from retaining the CPU quota
descriptor (`cpu.max` on cgroup v2) at startup. The inspector and preparation
worker share the strict descriptor check. That policy remains in force.

The grouped API and helper validate separate, typed bootstrap descriptors. They
do not call the migration worker's descriptor enumeration. They use the same
executable and therefore share its scheduler default.

The Preview systemd units have no CPU quota today. If a quota is introduced,
revisit this decision and qualify the scheduler behavior and the worker
descriptor checks together. Linux still enforces any configured quota.

CI executes both real worker roles inside a CPU cgroup and checks their open
descriptors. It also passes an extra descriptor to verify that both roles reject
it before accepting a control request.

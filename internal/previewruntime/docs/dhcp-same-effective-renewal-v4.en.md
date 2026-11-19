# Internal same-effective DHCP renewal

Development prerequisite, disabled by default. Only trusted assembly may select
`RoutedDHCPSameEffectiveRenewalV4` before owning any lease/gate/work. This change
does not enable a factory, an administrative setting or an installed runtime.

A new authenticated epoch/sequence may refresh only the same canonical owner,
interface and complete effective L3 delta. The selected Work remains immutable
provenance and undo. Forwarding and the old token are closed and read back before
the evidence refresh. Opening requires current authority, policy, full integrity
readiness and the fresh sequence; an irreversible fence cannot be reset.

There is a brief interruption per renewal. Persistent TCP/UDP survival, each
interruption and min/median/max, packet observations and native resource costs
remain qualification gates. The owner decides the acceptable maximum after
measurement; this component does not claim loss-free access.

After incomplete inspection, the controller requests `refresh_only` with retained
Work correlation before reading the owner. The helper verifies ownership and
closes before readiness, current-owner or snapshot checks that can fail. This
lane can refresh evidence while remaining closed; it never opens, creates Work,
withdraws selected configuration or starts a replacement acquisition.

Retiring a renewed V4 instance verifies the original baseline and selected
withdrawal, releases its L3 lease and retains the same closed gate/watermark.
That runtime is terminal: Begin and profile changes are rejected. Normal helper
resource cleanup releases the closed gate; uncertain closure/fence remains an
error. Recovery using a new acquisition identity belongs to a later contract and
behavior PR, not this prerequisite.

Owner calls cancelled before writing a frame consume no sequence and keep the
private channel usable. Errors after an exchange starts retain strict fencing.
Tests use real session/codec/controller/scheduler and Gate paths with controlled
kernel/store doubles. No daemon, periodic worker, dependency or storage format
is added; integrated native/resource qualification is pending.

The B2 native fixture revision 2 starts with a supported 71-second lease and
pre-existing TCP/UDP flows. Profile 70 changes only its lab peer, requires one
actual natural RENEW70 while forwarding stays closed, and retires before the
authenticated conservative trial deadline. Profile 71 briefly pauses only the
pinned Go acquisition owner to provoke late dispatch, then requires an actual
natural RENEW71 and fresh Open on the same sockets. The pause must be below
1.7 seconds; jitter, owner RPC errors, expiry or uncertain cleanup fail the
entire test. BOUND after EXPIRE is reacquisition and cannot count as renewal.
The versioned wrapper rejects old fixture results. These are test-only
acceptance scenarios; passing native/resource qualification remains pending.

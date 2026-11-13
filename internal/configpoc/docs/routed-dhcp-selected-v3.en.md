# Selected DHCP lease work (experimental)

The optional `configuration.routed-dhcp-selected.v3` feature stores DHCP work in
the existing configuration selector and three recovery-reserve pools. Static
records omit the new fields. Older readers reject the required feature.

Work binds the boot/run/namespace identity, exact network revision and LAN
baseline, owner PID/start/incarnation, DHCP epoch, controller sequence, original
absolute BOOTTIME deadline, and owned WAN address/default route. A hash is only
correlation. The helper's independent G1/R2 reader must issue selected authority
before effects; the writer verifies private authenticated helper readback.

The first implementation closes the gate and forwarding, withdraws the previous
WAN to the observed baseline, archives its terminal R2 work through both selected
anchors, and only then prepares a new grant. This interrupts renewal and does
not provide the existing executor's zero-L3-change renewal optimization. Prepared,
applied and withdrawn phases are audited. A persisted terminal witness prevents
reusing the same epoch/sequence; no Confirm or rollback restores an old token.

Restart requires the trusted recovery capability to close the gate, independently
resolve selected work and withdraw only the exact owned WAN delta. Missing proof,
drift or a different boot/run blocks opening. `withdrawn` means the original LAN
plus empty WAN was observed; it does not mean an earlier lease was restored.

Current evidence: unit tests use real selected-store files and reserve pools with
an explicitly simulated kernel authority. They cover repeated archive/reuse,
replay, authority loss, wrong phase, and wrong boot. Native selected-DHCP runtime,
LAN bootstrap and authenticated transport qualification remain pending. Kernel
timeout qualification assumes continuous execution; suspend, VM pause and
snapshot restore are unsupported. No host network adoption is enabled.

The separate Version 3 LAN bootstrap profile reuses the selected Boot/R2 path.
Read-only preparation requires both IPv4 interfaces empty. Only the static LAN
address is applied after deny-policy readback; WAN remains empty until selected
lease work. Local inventory declares LAN only. Lease withdrawal does not grant
LAN ownership: restoration additionally requires the original selected Boot
snapshot. Tests cover this ordering, partial-effect compensation and unconfirmed
Boot expiry with explicit kernel doubles. Native qualification remains pending.

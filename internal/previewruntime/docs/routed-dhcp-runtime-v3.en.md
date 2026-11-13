# Selected DHCP runtime V3

Experimental integration for an exclusively owned, non-host network namespace.
Static profiles retain their existing protocol and snapshot semantics. This is
not host-interface adoption, a DHCP server, NAT, DNS or suspend-safe forwarding.

Root assembly supplies `RoutedHelperOptionsV3.DHCP`: the selected LAN bootstrap
adapter, pinned target/host descriptors, canonical desired network, fixed owner
identity and `Current` callback. That callback must authenticate the separate
DHCP owner's inherited single-writer channel, PID/start/incarnation, sequence
and original absolute BOOTTIME deadline. The API cannot supply these facts.
The API opts in through `RoutedDHCP` and obtains `runtime.DHCP`; trusted assembly
calls `Reconcile(ctx)` for owner events and `Withdraw(ctx)` before conflicting
configuration changes. There is no public HTTP lease endpoint or automatic
producer connection in this increment.

The private channel negotiates `routed_dhcp_selected.v3` after integrity and
inventory capabilities. Begin/current have empty requests. Apply/open/withdraw/
live carry only the selected work hash; verify carries snapshot hash and state;
retire is empty. The helper independently reads the complete selected G1/R2
graph before effects. A hash is a locator, never ownership proof.

Sequence: close gate and forwarding, capture the authenticated grant, select
prepared work in the existing store, apply WAN, verify actual state, select
applied work, stage and read the bounded kernel token, open without recreating
it, then enable forwarding with gate/policy verification. Renewal currently
withdraws and archives the previous WAN before applying the next grant, causing
an interruption even for the same address. Unchanged authority only verifies
the existing token; it does not extend its deadline.

Owner loss or a persistent integrity fence closes and withdraws through the
retained helper. Kernel expiry does not depend on the API/helper remaining
alive. Selected recovery runs before LAN boot recovery, withdraws only the
authenticated WAN delta, archives it, then releases the LAN adapter's lease
lane. A closed gate may be reconstructed from an exact selected withdrawal
terminal, never from a live token. A different namespace requires fresh scope
proof; normal same-BootID service restart and scope retirement remain a separate
integration gate. A failed proof leaves recovery blocked.

Validation: focused race tests cover channel negotiation, rejected request
authority, actual selected-store history, lifecycle ordering, owner loss,
withdrawal, replay, closed-gate recovery and unowned forwarding rejection.
Runtime unit tests use explicit kernel/owner doubles; they are not native
forwarding evidence. Reproduce with:

```sh
go test -race ./internal/networkexecutor ./internal/firewallipc ./internal/configpoc ./internal/previewruntime -run 'Test(RoutedDHCP|LeaseSelectedV3Archived|LeaseForwardingV3|RoutedCodecV3|RoutedSessionV3)' -count=1
go vet ./internal/networkexecutor ./internal/firewallipc ./internal/configpoc ./internal/previewruntime
```

Pending: native producer-to-selected-runtime qualification, DHCP local-control
exceptions under the actual local policy, forwarding/sysctl profile readback,
same-BootID fresh-scope recovery, resource measurements and independent review.
Existing isolated lease/gate packet tests do not establish these combinations.
Continuous execution only: suspend, VM pause/snapshot and queued-packet removal
are not guaranteed. No production readiness or host activation is claimed.

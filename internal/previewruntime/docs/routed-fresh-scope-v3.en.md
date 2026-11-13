# Fresh scope after a normal service stop

Experimental selected-store integration distinguishes an OS boot from a managed
service incarnation. The same BootID may start a different RunID and gateway
namespace only with an authenticated root retirement receipt and actual empty
IPv4/table/readback evidence. Static snapshot ownership rules remain unchanged.

Root preallocates a 4096-byte regular slot, owner/group 0:0, mode 0600, one link,
no ACL. After waiting for children and closing the old namespace, root writes
`RootRetirementReceiptV3` in place and fsyncs it. The codec contains old scope,
metadata digest, original BOOTTIME drain timestamp and a digest over canonical
JSON without its integrity field; spaces complete the fixed-size slot. This
digest detects incomplete writes. Root FD provenance authenticates the issuer.

Root binds the full 4096-byte digest to its newly created identity, passing only
an O_RDONLY descriptor and `RoutedFreshScopeBindingV3` to the helper. The helper
duplicates and rechecks the descriptor, independently reads the selected work,
reuses `PrepareBoot`/`Observe`, requires no tables at all (including lease gate),
and observes closed IPv4/IPv6 forwarding. Root must delay DHCP motor sockets
until LAN boot; the existing real empty-listener check is not bypassed.

Helper assembly calls `PrepareServiceRestartViewV3` with the old identity from
the verified receipt. Its selected Target/Saved metadata configures the existing
engine; `Saved` must not be replaced by Startup. The private `prepare_boot` path
rereads selected work and receipt and checks the requested target/baseline before
readonly preparation. Metadata alone never authorizes an effect.

The API negotiates `routed_fresh_scope.v3` with integrity and inventory; DHCP is
independent. `fresh_scope` accepts only a selected work reference. There is no
request-supplied receipt, identity, deadline or proof flag. The existing store
records sticky `configuration.routed-fresh-scope.v3`. DHCP ends as `scope_retired`,
not `withdrawn` or `restored`, retaining original work and grant deadline. Boot
retains pending confirmation outcomes and deadlines. A service restart preserves
selected Running, LastGood and Startup, even when Running differs from Startup.
Pending commits roll back to their exact selected Previous; they are never
implicitly confirmed. The typed restart record binds the original source and
receipt; the helper derives the same target from its full selected read before
effects. OS reboot still selects Startup and is not enabled by this same-Boot
receipt profile. Selected history and the helper's retained receipt must
agree; an IP match or old token is insufficient.

Focused tests use real selected-store files/reserve pools and explicit physical
authority doubles. They cover same-Boot completed/pending restart, preserved
deadlines, exact retirement audit continuation, rejected caller proof and bad FD
shape. Native root drain/receipt/FD/namespace-to-helper qualification and resource
measurements remain pending. Root death without a completed receipt fails closed;
ExecStopPost/crash cleanup is a separate unresolved gate. Suspend, VM pause and
snapshot recovery remain unsupported. No host activation is claimed.
Repeated stops while an earlier boot-boundary recovery is still pending can
retain both System slots; a further boundary remains blocked until separately
proven retirement is available. This increment does not discard those reserves.

```sh
go test -race ./internal/configpoc ./internal/previewruntime ./internal/firewallipc -run 'Test(RoutedFreshScopeV3|RootRetirementReceiptV3|RoutedOSBootBoundary|ColdContinuationV1)' -count=1
go vet ./internal/configpoc ./internal/previewruntime ./internal/firewallipc
```

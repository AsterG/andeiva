# Selected retirement across an OS boot

Experimental v4 is separate from same-Boot service restart v3. A service restart
preserves Running or rolls back an unconfirmed operation. A new OS boot selects
Startup. Neither path restores an old DHCP lease or reopens an old timeout token.

Root must have completed its normal stop and written the exact 4096-byte v3
retirement receipt after draining processes and retiring the old namespace. The
v4 helper receives its O_RDONLY root-owned descriptor and a root bootstrap
binding to the full file digest and actual new identity. It checks the current
kernel BootID, owned nonhost namespace and unchanged service UID/GID. Old and
new BootIDs and RunIDs must differ. Namespace inode numbers may repeat between
boots; every identity still requires its own namespace to differ from its host.

`RoutedRebootScopeEvidenceV4` labels old drain and new observation BOOTTIME values
separately. Both must be positive; their magnitudes are never compared. Old lease
deadlines remain immutable history and never become remaining lifetime in the
new boot. The existing selected store records sticky
`configuration.routed-reboot-scope.v4`, exact work/identity/receipt/readback and
`scope_retired`. This does not claim `withdrawn`, compensation or restored WAN.

The full G1/R2 reader must find exactly the current selected old work. A stale
receipt cannot skip an incarnation. `PrepareRebootScopeViewV4` derives Startup,
Saved and work for trusted engine assembly. The helper then independently proves
empty tables/IPv4 scope, closed forwarding and existing real listener checks.
Private `routed_reboot_scope.v4` negotiates separately from v3; `reboot_scope`
accepts only a work reference. No caller supplies boot flags, clocks or proof.
Persistent integrity fencing and the opaque attach anchor remain mandatory.

The old DHCP terminal is archived through the existing reserve/selector path
before new Boot work can apply LAN. WAN remains without selected lease authority;
only a fresh grant from the new owner can permit its later activation. Pending
operation outcomes and original UTC confirmation deadlines stay unchanged.
Unproven interrupted boundaries/reserves are not freed, and missing/torn/stale
receipts fail closed. Power-loss, suspend and VM snapshot recovery are not claimed.

Tests use real selected-store files and reserve pools, with explicit physical
authority doubles and pipe protocol doubles. They cover new-clock values below
old ones, reused inode numbers, retirement before LAN bootstrap, Startup versus
Running, old-work immutability, pending UTC deadlines, corrupt G1, wrong scope,
unattached/fenced requests and v3/v4 separation. Native complete OS reboot,
root FD handoff, packet continuity and CPU/RAM measurements remain pending.

```sh
go test -race ./internal/configpoc ./internal/firewallipc ./internal/previewruntime -run 'TestRouted(RebootScopeV4|FreshScopeV3)' -count=1
go vet ./internal/configpoc ./internal/firewallipc ./internal/previewruntime
go build ./...
bash scripts/check-config-platforms.sh
```

# Boot attestation after an abrupt power loss

ADR-057 requires a root receipt proving that the previous grouped scope was
drained before a new scope may replace it. A power loss leaves the persisted
scope record (`grouped-scope-v3`) intact and the receipt slot
(`grouped-retirement-v3`) empty or naming an earlier scope. ADR-074 approved a
second proof for that case only.

## What the launcher does

Before releasing the previous scope record, the system launcher reads the
kernel boot identity directly from procfs and compares it with the record.

The packaged unit may mount exactly `/proc/sys/kernel` read-only. The launcher
rejects a separate read-only mount of the entire `/proc/sys` tree.

- Same boot identity: nothing is written. This is a service restart and the
  orderly drain receipt remains mandatory.
- Different boot identity: the launcher writes a boot attestation into the
  receipt slot. It names the recorded scope, the digest of that record, the
  accounts of this installation and the boot identity that issued it. Only then
  is the record released and a new scope created.

The attestation never claims that the old scope was drained. It states that the
scope belongs to another kernel boot of the same installation.

If power is lost again during recovery, the selected store may still name the
first scope or already the interrupted replacement. The launcher therefore
keeps up to eight recorded scopes, newest first, and issues the list again for
each new boot. An orderly drain receipt replaces the attestation.

## What the helper verifies

The helper receives the slot as a read-only descriptor bound by digest to the
new scope. It independently reads the kernel boot identity, requires the
attestation to be issued for that identity and for its own accounts, and
requires the scope named by the selected store to be one of the recorded
scopes. It then verifies the complete selected history and that the new scope
is closed and empty, exactly as it does with a drain receipt.

Evidence persisted with the boot plan is marked `boot_attested` and carries no
drain time. A store holding such evidence declares the required feature
`configuration.routed-boot-attestation.v4`.

## What stays closed

A record of the running boot without a drain receipt, a damaged or tampered
record or slot, a record or attestation from other accounts, a scope the
launcher never recorded and a corrupt selected history keep the service closed
and require authorized offline maintenance. Web, CLI and API have no part in
this proof.

## What the coordinator does with the proof

With a valid proof for a scope of another kernel boot, an interrupted Commit or
Confirm and a rollback that never completed receive their ordinary terminal
record without any engine effect, and the saved Startup is then booted in the
new scope. The deadline, lease and marks of the previous boot are not consulted.
A scope replacement whose Startup boot an earlier boot had already verified is
finished from the records that boot left. A completed boot accepted from an
attestation adds one protected audit entry, `boot_attestation` with result
`accepted_without_receipt`. Startup and this event are selected together so the
event survives a further power cut after Startup completes.

Each step can be interrupted and repeated on the next complete boot, with one
exception: a scope replacement whose own Startup boot was still selected when
power was lost again stays closed.

## Limits

The administrator notice in the web interface is not implemented; the audit
entry is the only record shown. The slot is written in
place: a write torn by a power loss leaves it unreadable and the service
closed. If a scope started after a power loss stops in an orderly way before
the store completed its recovery, the drain receipt replaces the attestation
and the next start is refused. Abrupt power cuts on real hardware have not been
qualified.

## Upgrade and rollback

Before installing the update, stop the grouped service and verify its orderly
drain. Keep a verified backup of the previous package, selected store and
operational records from that same stopped installation. A legacy scope record
can be cleared only with its exact orderly receipt. A legacy boot attestation
and unknown record formats keep recovery closed.

The new scope record binds the node and verified cutover to the previous slot's
digest. Each retained entry in a new boot attestation carries the installation
digest. The helper receives the expected values through its authenticated
bootstrap. It checks the installed origin against the selected store, matches
the gateway MACs and compares every entry with the expected digest.

Earlier binaries reject the new root record formats. To roll back, have an
authorized operator stop and drain the grouped service. Restore the earlier
package and its matching, verified stopped backup using the offline recovery
procedure. Keep forwarding closed until the restored Startup and kernel state
have been verified. Restoring the backup discards changes made afterward.

## An interrupted transaction with WAN DHCP

On a verified complete boot, the helper proves retirement of both the DHCP
scope and the selected transaction scope. The store detaches the continuation
and keeps the existing reservations until the unfinished operation and the
DHCP Work have been archived. The helper verifies the resulting continuation
before applying Startup. WAN obtains a new lease after Startup is verified.

When the first reservation belongs to a different, verified kernel boot, its
counter starts at the previous high-water mark. Every assigned mark is new.
Exhaustion returns `ANDEIVA_OPERATION_LIMITED` before lease admission or
changes to forwarding. Service restarts keep their existing restrictions.

Older readers reject stores that require either new recovery feature. For a
downgrade, restore a verified offline backup from before the first use of
those features with the matching package and operational records. Verify
Startup before returning the appliance to use.

# Boot attestation after an abrupt power loss

ADR-057 requires a root receipt proving that the previous grouped scope was
drained before a new scope may replace it. A power loss leaves the persisted
scope record (`grouped-scope-v3`) intact and the receipt slot
(`grouped-retirement-v3`) empty or naming an earlier scope. ADR-074 approved a
second proof for that case only.

## What the launcher does

Before releasing the previous scope record, the system launcher reads the
kernel boot identity directly from procfs and compares it with the record.

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

## Limits

This document covers the proof only. Archiving an interrupted Commit, a failed
rollback or an unfinished scope replacement and selecting Startup for them is
not implemented yet; those states still stop at start. The slot is written in
place: a write torn by a power loss leaves it unreadable and the service
closed. If a scope started after a power loss stops in an orderly way before
the store completed its recovery, the drain receipt replaces the attestation
and the next start is refused. Abrupt power cuts on real hardware have not been
qualified.

# Selected-work helper transport

Protocol3 is a separate prepared transport for grouped configuration. It never
falls back to independent legacy writers. Only an authenticated supervisor Unix
channel may reach it; inherited wrappers verify kernel UID, GID and PID.

The unprivileged client sends canonical preparation data or a work reference.
The helper independently resolves complete selected correlation, G1, reservation
banks, scope and action. A work hash or serialized boolean is not authority.
Work generation differs from global selection generation. Read-only preparation
compares the requested baseline expectation with independently loaded Startup,
saved witness and baseline. No request supplies paths, commands, TTL or identities.

A single controller owns dispatch through reply completion, even after client
disconnection. A new writer must finish the handshake before opening its store.
A failed/lost reply closes the client without replay or deadline renewal. The
helper guardian remains independent. Frames are bounded to three256KiB artifacts
plus4096bytes; v1/v2 bounds stay unchanged.

Unit/race tests cover malformed frames, scope/sequence mismatch, unverified plans,
controller fencing and real Unix peer credentials. Those tests use fixture engines;
they are not evidence of native nftables, different-process selected-store access
or permanent runtime activation. Shared-store integration and native deployment
remain separate gates. Resource qualification of the assembled helper is pending.

```sh
go test -race ./internal/firewallipc ./internal/previewruntime -run 'TestRouted(Codec|Client|Reply|Session|Inherited)V3' -count=1
go vet ./internal/firewallipc ./internal/previewruntime
```

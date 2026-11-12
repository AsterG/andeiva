# Prepared scoped helper IPC v2

[Español](SCOPED_V2_ES.md) · [Português](SCOPED_V2_PT.md)

This prepared transport is not selected by the deployed runtime. Version 1
constructors, frames and recovery behavior remain unchanged. No public API,
service account, systemd unit, host rule or namespace is changed by this slice.

## Boundary and behavior

The explicit v2 handshake binds runtime run, helper incarnation, epoch, fixed
domain and namespace. Its required features are exactly `attach_observed.v1`
and `recover_scoped.v1`, in that order. Each bounded frame repeats those
bindings and the ordinal sequence. There is no downgrade or v2 `recovered` verb.

Payloads are discriminated by fixed verbs. Strict decoding rejects duplicate,
case-aliased or unknown fields, trailing JSON, invalid revisions and
noncanonical recovery deadlines. Requests and ordinary replies remain within
64 KiB; Local-In observation replies have the existing 256 KiB ceiling.

`attach_observed` compares phase, ID, hashes, original deadline and actual
effective hash under the guardian mutex. It neither applies nor restores policy,
clears a lease, extends a deadline nor completes durable recovery. An expired
but not yet reconciled active phase is rejected without performing expiry work.
Before attachment only state, observe and attachment are allowed.

The exact bootstrap state has empty metadata, zero deadline and empty engine
identity. Attachment then enables only the one-time canonical bootstrap. Its
verified idle/nonempty result enables normal mutations. An initialized or
inconsistent bootstrap cannot use this exception.

`recover_scoped` invokes the existing guardian CAS for ID, previous/target hashes
and original deadline before compensation. A replacement lease, including the
same ID/hashes with another deadline, is not consumed. No v2 path invokes legacy
unscoped recovery. Existing leases can be observed and rebound below 500 ms
without rearming; new Arm retains its 500 ms minimum and 120 s maximum.

The session admits one controller before spawning connection work, retains the
guardian across disconnects and assigns monotonically increasing epochs. A
fatal listener error closes the active controller before waiting for workers.
Calls have a five-second client bound; started helper frames and operation
contexts retain three-second bounds. A failed, malformed, timed-out or lost
exchange closes the client. Mutations are never automatically retried. A new
epoch observes actual state; it does not invent a completed operation receipt.

## Authentication and assembly limitations

`ConnectV2`/`ServeV2` require a channel already authenticated by trusted assembly;
they do not authenticate arbitrary streams. The prepared Unix wrappers reuse
socket metadata and kernel peer checks. Inherited wrappers additionally compare
the expected kernel PID/UID/GID before negotiation. Socketpair credentials
identify the creator, not every later FD holder: existing launch validation of
FD provenance, supervisor, aliases, namespace and privileges remains mandatory.
The wrappers do not replace that validation or activate `localruntime` children.

Single-session admission is not exclusion of a second helper process. Runtime
cutover must independently enforce one authority, subject realm, namespace/table
owner and selected protocol. Cold migration, Local-In proof binding and deployed
coordinator integration remain separate gates. Protected audit/export authority,
storage reclamation and physical recovery reserves are not changed.

## Reproduction and evidence

On Linux/WSL with Go 1.27.4 and dependencies available offline:

```sh
GOPROXY=off GOSUMDB=off go test -race -buildvcs=false ./internal/firewallipc ./internal/previewruntime ./internal/nftguardian -count=3 -timeout=5m
go vet ./internal/firewallipc ./internal/previewruntime ./internal/nftguardian
go build ./cmd/... ./internal/...
```

Tests exercise real private Unix connections and inherited socketpairs with a
real guardian and simulated engines. They cover cold attachment/bootstrap,
scoped recovery, independent expiry, short-lease rebind, replacement leases,
stale attachment, lost replies, strict framing/correlation, peer rejection,
Local-In observations, burst admission and listener-exit cleanup. They do not
establish real kernel/listener effects, OS reboot, power-loss safety or deployed
parity. Native Debian resource measurements and runtime activation remain
pending qualification; no production sizing claim follows from these fixtures.

Before activation, rollback is removal of unused prepared code. After a future
v2 cutover, do not fall back to a live v1 writer while protected work is unresolved.

# Capless routed management assembly

`OpenRoutedOperationsRuntimeV3` is a trusted Linux assembly factory, not an HTTP
operation or installer switch. It consumes two distinct inherited Unix sockets
and their supervisor-authenticated helper PIDs. Launch must retain and validate
FD provenance; request data never supplies a socket path or identity.

The API must pass existing exact UID/GID, empty capability and `NoNewPrivs`
checks in the host namespace. The factory requires the pinned shared-reader
store profile, three pre-opened reserve pools and absolute guard deadlines.
The grouped v3 handshake fences a previous controller before the compatibility
v2 handshake, snapshot attachment or configuration writer opens. Both channels
are required: v2 is retained only for existing schema4 engine compatibility;
there is no negotiation, automatic replay or fallback.

The factory injects a remote grouped authority bound to trusted boot/run/namespace
metadata. Caller-provided grouped authority is rejected. Canonical store and pool
checks remain in the existing coordinator. Their roots/pools/local engines stay
caller-owned. Both sockets transfer to the factory on entry and close on failure.
Runtime close releases only the management writer and channels; effective rules,
namespaces/listeners and helper deadlines remain independent.

Tests use actual Unix peer credentials and real transport with simulated engines.
They verify handshake ordering, identity/profile rejection before store writes,
and preservation of effective helper policy on management close. They do not
qualify full shared-store assembly, packet traffic, installation or OS reboot.

Run on Linux: `go test -race ./internal/previewruntime -run TestRoutedAPIV3 -count=1`.
No deployed runtime or unit is enabled by this factory.

Metadata and shared-directory profile prechecks read identity only before the
handshake; they open no configuration writer or lock and perform no writes.
Distinct helper PIDs are permitted only as supervisor-pinned launch inputs.
This factory does not implement that supervisor launch/provisioning path.

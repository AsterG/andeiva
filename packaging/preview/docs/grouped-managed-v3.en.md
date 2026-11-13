# Managed gateway assembly

The native launcher owns a fresh gateway namespace and two private child links.
Physical parent bindings include index, name, hardware address and MTU. A separate
node-local identity keeps child MAC addresses stable across supervisor RunIDs;
it is not a credential or shared policy. Existing namespaces are never adopted.

Only positively identified child links may be raised or removed. The launcher
sets no address, route, NAT or forwarding policy. IPv6 and forwarding are closed
before link creation. The transaction engine remains responsible for L3 effects
and effective-state verification. API processes remain in the management namespace.

A root cutover record binds the operational deployment and node-link manifests.
This record is not a G1 proof: selected configuration and independent helper
readback must still pass. The namespace is removed only after the inherited
supervisor drains its children. Unknown runtime files prevent cleanup/restart
instead of being deleted. Package installation does not create an activation
record or enable the incomplete grouped service.

Automated tests cover bindings, manifest hashes, link replacement, cancellation,
lost acknowledgements and idempotent cleanup. Installed lifecycle, cold cutover,
DHCP bootstrap and client Internet acceptance are separate qualification gates.

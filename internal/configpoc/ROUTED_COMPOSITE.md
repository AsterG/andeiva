# Routed composite references

The prepared schema 7 resolver binds a firewall revision (schema 4 or 6) and a
local-services revision (schema 3). For schema 6, its network reference must equal
the canonical network embedded in that exact firewall payload. Schema 4 requires
a null network reference. Network is a derived view, never a second writer.

Resolution reads at most two component objects through the caller's bounded
reader. It checks schemas, canonical bytes and hashes, preserves storage errors
and returns a detached reference document. Existing schema 5 canonicalization is
unchanged and continues to reject schema 7.

This is model validation only. It does not enable a store feature, migrate state,
expose an administrative operation, apply addresses or activate traffic policy.
Runtime migration must additionally qualify grouped Candidate/Running/Startup,
one scoped activation authority, recovery, protected audit and storage budgets.
Independently confirming several helpers does not provide group rollback.

Future routed operations must explicitly include firewall and local services in
the same bundle, preserve unrelated work and require confirmation for initial
network changes. Saving Running to Startup remains explicit. A successful model
validation is not evidence of connectivity, listener availability or authorization.

Run the portable model tests and the existing envelope compatibility tests:

```sh
go test -race -count=1 ./internal/configpoc -run 'TestRoutedComposite|TestRoutedEnvelope'
go vet ./internal/configpoc
```

These tests use in-memory component readers and no privileged network operations.
Full coordinator, runtime and native cutover acceptance remain separate gates.

[Español](ROUTED_COMPOSITE_ES.md) · [Português](ROUTED_COMPOSITE_PT.md)

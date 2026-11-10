# Confined Local-In nft transport

This implements the `localengine.Transport` method contract. It is an internal
executor boundary, not an API for user-supplied nft input. Only the canonical
Local-In compiler may provide batches. The current compiler emits JSON, so the
transport invokes the fixed `/usr/sbin/nft` executable with `-j -f -`, adding `-c`
for validation. No shell, administrator-selected executable, table or argument
is accepted.

`New(namespace, host)` must run inside the owned gateway namespace. It verifies
the current namespace and inherited FD3 identify the same network namespace,
different from the supplied trusted host identity. Real/effective/saved/filesystem
UID and GID must match the nonroot process. Inheritable, permitted, effective,
bounding and ambient capabilities must each contain only NET_ADMIN;
`no_new_privs` must be set. These conditions are checked before and after every
command. The executable and resolved parent directories must be root-owned and
not group/world writable. The supervisor remains responsible for authenticating
the run, supplying the actual host identity and retaining the owned namespace.

`Check` admits only bounded compiler-shaped JSON: optional deletion of exactly
`inet andeiva_local`, its tagged table declaration, one INPUT filter chain at
priority 10 with drop policy, and ordered scoped service/ND rules. Unknown
operations, extra fields, commands, hooks, jumps, NAT, broad source prefixes,
unscoped ND, duplicate IDs and arbitrary expressions are rejected. Policy
metadata and exact service authorization are still the canonical engine's
responsibility; this layer cannot reconstruct the source configuration from
packet expressions. Kernel readback must subsequently pass
`localnft.VerifyObservation` against the independently compiled artifact.

A successful check grants one apply attempt for exactly those bytes. Changed
input, another check, an observation, failure or an apply attempt invalidates the
previous permit. Apply errors may occur after a kernel commit and must be treated
as uncertain by the coordinator; they never prove rollback or absence.

`Observe` first runs `nft -j list tables`. Absence is returned only after that
command succeeds and its complete bounded response validates. If present, a
second fixed command lists only `inet andeiva_local`. Failure of either command,
malformed JSON, duplicate objects, a foreign family, or a table disappearing
between queries returns an error. A comment alone never proves effective rules.

Every invocation has a three-second command deadline and a 100 ms pipe-drain
grace, honors earlier caller deadlines, bounds stdout/stderr, uses a fixed environment and a parent-death
signal, and suppresses command diagnostics from returned public error codes.
Only successful stdout is returned. Stderr output, overflow or cancellation is
an error. The caller must never turn these failures into a successful commit.

```sh
go test ./internal/localtransport
go test -race ./internal/localtransport
go vet ./internal/localtransport
```

Tests use a private injected executor and inspect command construction; they do
not execute privileged network operations. Linux privilege/parser tests read no
foreign process and apply no rules. Native capability inheritance, nft parser
compatibility, effective readback, recovery and resource consumption require the
authorized Debian laboratory. This package provides no production-readiness claim.

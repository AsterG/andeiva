# Configuration transaction experiment

[Español](es.md) · [Português](pt.md) · [Design and acceptance matrix](../README.md)

This guide is for a trusted local development environment. The experiment changes
temporary configuration files and simulated component state. It does not configure
a real firewall, proxy, network interface or production ANDEIVA service. No root
privileges, Docker runtime or network access to an appliance are required.

## Run the checks

Use Linux with Go 1.27.3 already installed and a compiler suitable for the Go race
detector. WSL is suitable for development checks; use its Linux filesystem for
persistence tests, not a Windows-mounted directory. Missing prerequisites are a
blocker; do not weaken the tests or make the appliance install build tools.

From the source root:

```bash
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOTELEMETRY=off
go test -race -count=1 -v ./internal/configpoc
go build ./internal/configpoc
```

Record the source commit, Go version, operating environment, complete test output
and exit status. A successful build proves compilation only. Skipped tests and
unexecuted failure scenarios are not passes. Temporary test stores belong to the
test harness; never substitute an appliance data directory.

Run the standalone scenario with a new private directory on the Linux filesystem:

```bash
umask 077
poc_parent=$(mktemp -d /tmp/andeiva-config-poc.XXXXXX)
go run ./cmd/andeiva-config-poc -state-dir "$poc_parent/state" -iterations 20 > "$poc_parent/report.json"
cat "$poc_parent/report.json"
```

The command accepts 1–100 iterations and emits one JSON report containing scenario
assertions and resource observations. It requires a new absolute state path and
an unprivileged Linux user. Retain the directory and report for inspection. It
does not remove an existing store, install services or apply real engine rules.
Use a canonical path without `.` or `..`, repeated separators or symlink
components. The parent directory must already exist and remain trusted; invalid
paths are rejected before directory creation.

## State transitions and authority

`stage` creates Candidate. `validate` checks it without changing Running.
`commit` coordinates component application and advances Running only after success.
With a confirmation window, that revision remains provisional until `confirm`;
expiry triggers compensation. `save` explicitly copies Running to Startup and is
not permitted to bypass pending confirmation. `recover` attempts reconciliation
when the effective state cannot be trusted. `revoke` is protected state independent
of ordinary configuration saving.

These are typed service operations exercised by tests, not implemented commands
of the installed `andeiva` CLI. The Web, CLI and API surface labels use the same
service permissions. The harness supplies trusted identities; it does not test
real browser sessions, HTTP authentication, MFA or SSH identity.

Reopening a process and booting a system are separate cases. Process recovery
uses durable transaction state; explicit boot selects Startup. An unconfirmed
transaction is conservatively rolled back after restart. Audit and revocations
must survive without requiring `save`.
The timer runs inside the controller. There is no independent watchdog or
engine-enforced lease proving deadline enforcement during a controller outage.

## Failures and recovery

Preserve a failing test's output and exact reproduction command. Do not remove a
lock, edit history, replace checksums or delete state to turn a failure into a pass.
If a store operation is uncertain, stop changes and reopen through the supported
recovery path. If a component cannot roll back, report recovery required; a partial
state is not a successful commit. A fresh test directory is appropriate for a new
isolated test, not a substitute for recovering the original failed case.

The store has finite capacity. Rejection at its bound preserves history; it is not
an automatic retention or backup policy. Under the writer lock, reopening checks
the entire committed history, all entries and matching `staging-v1.owner` and
`.andeiva-stage-v1/owner.json` metadata before removing the single orphan
`.andeiva-stage-v1/record.tmp`, limited to 1 MiB. The metadata identifies format
`andeiva.config.staging.v1` and a shared `store_id`; cleanup does not depend on Go's
temporary-file suffix. Committed audit records are never removed by this cleanup.

Unexpected or foreign files, legacy `.pending-*` files, mismatched metadata and
partial ownership initialization block opening and are preserved. There is no
automatic repair for these cases. Retain the original directory and failure output
for investigation; do not delete or edit markers, rename files into the staging
directory or remove unexplained files to make recovery pass. A process using the
same UID or root is outside this ownership boundary.

Configuration contents and raw diagnostic reports may be sensitive. Keep evidence
private and share only the minimum needed to reproduce a defect, with no
credentials or unrelated machine data.

## What the result means

Schema 3 adds canonical local-service declarations; schemas 1/2 retain their exact
bytes and hashes and cannot carry these declarations. Migration requires staging
and commit, never an automatic journal rewrite. Changes to local services and any
historical rollback involving schema 3 require a confirmation window (30–120
seconds through the managed boundary). Expiry or restart while pending restores
the previous Running revision; Save is rejected until confirmation. Legacy-only
rollback stays immediate. OS boot selects saved Startup. These are coordinator
contracts, not evidence of running HTTPS/SSH listeners or kernel enforcement.

File I/O, process lifecycle, locking and the common authorization service may be
real; component application remains simulated. Record those categories separately.
Measure CPU time, resident memory, disk growth and operation latency for the actual
test workload. A small configuration benchmark is not packet throughput or an
appliance capacity certification.

Process interruption, file synchronization and restart tests do not establish
resistance to a physical power cut. This experiment does not select SQLite or
PostgreSQL, implement HA, sign history, encrypt secrets, provide production
authentication or validate real nftables/proxy coordination. Keep those gates open.

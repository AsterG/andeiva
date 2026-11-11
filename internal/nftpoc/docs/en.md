# Debian laboratory procedure

Validated scope and measurements are recorded in [the validation report](../VALIDATION.md).
Use this procedure only for the isolated experiment; it does not install an appliance firewall.

Run only on the authorized Debian 13 AMD64 development VM with a recoverable
snapshot and VMware console access. Do not run the privileged experiment on the
Windows host, WSL, Docker Desktop, a shared CI runner or a production gateway.
No Windows, VPN, host routing, host forwarding or host firewall changes are needed.

## Build and unprivileged checks

Use the repository's Go version, currently 1.27.4. From its root:

```bash
bash scripts/check-nft-poc.sh
go test -race -count=1 ./internal/configpoc
go vet ./cmd/... ./internal/...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -o andeiva-nft-poc ./cmd/andeiva-nft-poc
sha256sum andeiva-nft-poc
```

The adapter unit tests simulate nft responses. They do not authorize or perform
privileged network operations. Transfer the resulting binary by the authorized
laboratory channel and compare its checksum in Debian. No secret belongs in a
command, source file or evidence report.

## Install and execute

The VM must already provide `/usr/bin/ip`, `/usr/sbin/nft`, `/usr/bin/nsenter` and
`/usr/bin/setpriv`. Missing tools block the experiment; the runner does not install
packages or enable services. The binary and privileged executable paths must be
root-owned and protected against group/other writes. An unprivileged UID/GID is
used for the coordinator and traffic probes; no new privileged service is installed.
The current fixture requires the trusted laboratory account UID/GID 1000.
If sudo is unavailable, perform installation from an authorized local root console.

Inspect an existing installation before replacing it. For a fresh laboratory copy:

```bash
sudo install -d -o root -g root -m 0755 /opt/andeiva-nft-lab
sudo install -o root -g root -m 0755 ./andeiva-nft-poc \
  /opt/andeiva-nft-lab/andeiva-nft-poc
sudo /opt/andeiva-nft-lab/andeiva-nft-poc --run-lab --snapshot-confirmed
```

Use the snapshot flag only after verifying that recovery is available. The runner
creates a private evidence directory under `/var/tmp/andeiva-nft-poc-*` and reports
its exact path. Keep that path and the command's exit status. Do not infer success
from creation of the report or a single successful connection.

The fixture creates three unnamed network namespaces, private virtual links and
routes, and enables IPv4 forwarding only inside the private gateway namespace.
It creates the exclusive `inet andeiva_poc` table there. TCP and UDP listeners on
18080, 18081 and 18082 exist only inside the sink namespace. The normal VM's
interfaces, routes, forwarding, nftables tables and SSH are outside the fixture.

## Verify, clean up and recover

Read the entire report and compare expected versus observed cases: positive and
negative TCP/UDP probes, validation, commit, confirmation/expiry, compensation,
concurrency, process interruption, baseline preservation and cleanup. Keep audit,
source revision and resource samples private. An unavailable listener or broken
route is not evidence of successful firewall denial.

Normal cleanup stops only tracked fixture processes, releases the owned namespace
handles and verifies absence of references to those namespaces. No named namespace
or global network deletion is required. The report remains for inspection.

If the runner reports uncertain ownership, failed compensation or cleanup failure,
stop further experiments and inspect through the authorized VMware console. Do not
flush any ruleset, delete arbitrary namespaces, kill unrelated processes or modify
corporate routes. Preserve the report; use the known snapshot recovery procedure
if the fixture cannot be safely identified. Supervisor death, physical power loss
and recovery of a full appliance remain separate, unproven scenarios.

To remove the experimental installation after the runner has exited:

```bash
sudo rm -- /opt/andeiva-nft-lab/andeiva-nft-poc
sudo rmdir -- /opt/andeiva-nft-lab
```

There is no systemd unit to remove. Retain the evidence directories until reviewed.
For an update, finish and clean up the previous run, verify the new binary hash,
replace that one file and use a fresh test journal. Do not reuse an old journal
across catalog/compiler versions without an explicitly tested migration.

This is an IPv4 fixture test, not a production firewall. The existing Web page,
official CLI and liveness API do not gain management endpoints from this experiment.

## Observed results and limits

Two fresh Debian runs passed 15 scenarios each: 96 TCP/UDP checks plus 112
continuous denied probes. Host state matched before/after and all three test
namespaces were removed. Runtime was 59.4–59.8 seconds; maximum single-child RSS
was 13,076–13,420 KiB and journal size 189,813–189,816 bytes. This is not total
appliance memory or a throughput benchmark. Real kernel rollback was tested
after a simulated component failure; coordinator SIGKILL and expiry were real.
Lost helper-confirm acknowledgment remains simulated; full helper/supervisor
death, power loss and production authenticated Web/CLI/API are not validated.
An uncertain confirmation blocks subsequent mutations until a safe outcome can
be established; do not force recovery by deleting the journal or unknown rules.

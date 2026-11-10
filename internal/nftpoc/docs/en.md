# Debian laboratory procedure

Work in progress: the privileged procedure below has not been validated in Debian.
Do not execute it until the confirmation-failure safeguard and security review
listed in the experiment README are complete.

Run only on the authorized Debian 13 AMD64 development VM with a recoverable
snapshot and VMware console access. Do not run the privileged experiment on the
Windows host, WSL, Docker Desktop, a shared CI runner or a production gateway.
No Windows, VPN, host routing, host forwarding or host firewall changes are needed.

## Build and unprivileged checks

Use the repository's Go version, currently 1.27.3. From its root:

```bash
go test -race -count=1 ./internal/configpoc ./internal/nftpoc
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

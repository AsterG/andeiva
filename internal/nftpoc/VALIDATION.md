# Bounded nftables laboratory validation

Implementation tested: `58e4b1403a177887488183341160faec260b11f8`.
Two independent fresh runs used Debian 13 AMD64 in VMware Workstation, 2 vCPU
and 4 GiB RAM, nftables 1.1.3. Linux binary SHA-256:
`90d178e96fc7209f7fd6d9777bc0f435b8459bc1829a3bd6f90b47e8d50ed421`.
Raw journals, host inventories and operation logs remain private.

## Real kernel and traffic results

Both runs exited zero, passed all 15 scenario assertions and cleaned up their
three isolated namespaces. Each performed 96 TCP/UDP traffic checks and 112
additional continuously denied probes during repeated rule changes. Positive
controls checked healthy listeners; the unrelated sentinel table remained intact.

Observed scenarios: default deny; allowed and denied TCP/UDP; first-match order;
Commit; Commit Confirmed; expiry after actual coordinator SIGKILL; reopening the
same journal against the surviving helper/kernel; Running/Startup independence;
real nft rollback after a simulated second-component failure; invalid catalog
rejection; concurrent generation conflict; repeated atomic batches/readback;
durable audit; listener health; sentinel preservation.

External before/after captures matched for host addresses, IPv4/IPv6 routes,
ruleset, forwarding, SSH status and network namespace inventory. The helper
reported non-root UID 1000, precisely CAP_NET_ADMIN in all capability sets and
NoNewPrivs=1 inside the gateway namespace. No host forwarding, interface, route,
NAT or SSH configuration was changed.

The first run's independent evidence review verified 18 applied ruleset readbacks,
their revision bindings, and the hash chain of all 54 journal records. The terminal
journal had no pending confirmation or recovery flag. Observed packet delivery
is bounded evidence, not a universal proof of atomicity or security.

## Resource observations

| Measurement | Run 1 | Run 2 |
| --- | ---: | ---: |
| Elapsed seconds | 59.824 | 59.432 |
| Supervisor CPU seconds | 0.289 | 0.212 |
| Waited child CPU seconds | 2.789 | 2.562 |
| Maximum child RSS, KiB | 13,420 | 13,076 |
| Journal bytes | 189,813 | 189,816 |
| Successful commit duration range, ms | 79.170–111.248 | 74.679–135.496 |

CPU comes from getrusage, not a sampled utilization percentage. Maximum child RSS
is the largest child observation, not total concurrent process memory. Timing
includes the laboratory control path and audit. These are neither throughput
benchmarks nor production appliance sizing results.

## Automated and simulated checks

Go tests with the race detector, vet, formatting and Linux/Windows/Darwin builds
passed for the integrated implementation. Gosec reported zero open issues with
one narrowly documented G204 exception for validated self-exec. Unit tests cover
strict catalog input, readback drift, command boundaries, invalid privileges,
malformed/misbound IPC, artifact mismatch, uncertain confirmation followed by
Save, stale concurrent requests and reopen before/after confirmation expiry.
Existing configuration tests exercise registered temporary files and interrupted
journal writes. These fault injections do not prove native power-loss behavior.

Shared CI runs unprivileged tests and compilation only. The native runner requires
the explicit authorized laboratory and snapshot flags; it is not a CI job.

## Limits and reproduction

Follow [EN](docs/en.md), [ES](docs/es.md) or [PT](docs/pt.md). Use a fresh journal
for each complete run and preserve exit status, report, diagnostics and binary
hash. Installation adds only a temporary experimental binary, not a service.

Not established: whole-machine restart/power loss, guardian/supervisor death,
lost helper-confirm acknowledgment with a real nft process, native failed
compensation or malicious drift, asymmetric TCP/UDP policies in the native
matrix, IPv6 policy, connection tracking, production authorization or authenticated
Web/CLI/API transports. Lost-ack handling is covered by simulated engine and
real coordinator-process/journal regression tests. A trusted local UID1000 shares
the journal trust domain. Diagnostic helper logs are not the durable audit store.

No NAT, VPN, IPS, WAF, antivirus, HTTPS inspection or production firewall claim
is part of this experiment.

# Administrative firewall milestone — Debian laboratory

Validated on 10 November 2026 against implementation commit
`1fc14f7ca811569213d71837a80ca11c06c968e7` on Debian
13 AMD64 in VMware Workstation (2 vCPU, 4 GiB RAM). This is an experimental
administrative workflow using three isolated network namespaces, not a production
firewall or appliance deployment. No host firewall, forwarding, NAT, interfaces,
SSH configuration or routes were changed.

## Results

| Capability | Implemented | Native evidence |
|---|---|---|
| Authenticated administrator and viewer roles | Yes | Real HTTPS login, permission checks and logout; anonymous 401, viewer 403 |
| Create and edit IPv4 TCP/UDP rules | Yes | Browser-created rules; identical canonical rules in Web, CLI and API |
| Candidate, Running and Startup | Yes | Stage leaves Running unchanged; Save explicitly changes Startup |
| Validate, Commit, Commit Confirmed, Confirm, Save and Rollback | Yes | Each operation executed through Web, CLI and API; journal receipts and effective revisions checked |
| Effective nftables rules and traffic | Yes | Kernel readback and 26 TCP/UDP probes across two runs; Allow, explicit Deny and unmatched/reverse denial |
| Rule traffic observations | Yes | Same retained records across all three interfaces; six deltas correlated with probes |
| Audit and concurrent administration | Yes | 68 journal records and 177 authentication audit events; concurrent administrators produced one success and one configuration conflict |
| API interruption and restart | Yes | Pending recovery before expiry; separate expiry while API was stopped restored TCP/UDP before API restart |
| Complete laboratory restart | Yes | Saved Startup replaced an unsaved Running policy; fresh traffic stream and baseline |
| Cleanup | Yes | Both reports confirmed cleanup and host invariance; owned namespaces, runtime processes and HTTPS listener absent |

The independent evidence check validated 109 states, 674 revision digests, the
journal chain and 25 traffic pages. Final API and CLI state and traffic responses
were identical and agreed with the browser. IPv4/IPv6 routes and the host ruleset
were unchanged. Interface addresses matched after excluding only DHCP lifetime
countdowns; raw captures were preserved. SSH remained active and host forwarding
remained disabled.

Observed examples for explicit rules were TCP Allow +10 packets/+664 bytes,
UDP Allow +2/+184, TCP Deny +1/+60 and UDP Deny +1/+92. These are counters sampled
over an interval, not individual connections or packet timestamps. See
[the observation contract](TRAFFIC.md) for baselines, volatile retention and gaps.
Transactional audit is distinct from these traffic observations. Authentication
audit is retained separately; this change does not add an authentication-audit UI.

## Corrections and automated checks

Fresh provisioning under a restrictive umask exposed incorrect file modes and
failed closed during API startup. Provisioning now sets exact ownership and mode
on the open descriptor before writing and synchronizing. Regression tests cover
umask 077 and 027. A fresh native provision succeeded without manual permission
repairs; the runtime could not read operator credentials, and the operator could
not read the server key or account verifier file.

Go tests, the race detector, vet, formatting and Linux/Windows/macOS compilation
passed. Frontend lint, typecheck, build, 15 unit tests and 93 browser fixture tests
passed. Quality and Security passed for the tested implementation. Real browser
captures cover desktop/mobile Light and Dark; the approved logo is unchanged.
Native UI execution used English. EN/ES/PT, keyboard and accessibility checks in
the browser suite are fixture evidence, not additional native traffic runs.

## Resource observations

The final point sample measured API RSS at 17,376 KiB and helper RSS at 18,096 KiB.
Two fixture listeners each used 12,608 KiB. The journal directory used 411,836
bytes. The first run lasted 1,230.928 seconds: supervisor CPU 0.063203 seconds,
child CPU 5.126797 seconds, maximum individual child RSS 20,460 KiB. The second
lasted 80.628 seconds: 0.030159/0.762915 CPU seconds and 18,656 KiB maximum child
RSS. These include operator pauses and test processes; they are not throughput,
aggregate peak memory, incremental overhead or capacity benchmarks.

The frontend production JavaScript increased by 10.06 kB (2.92 kB gzip); CSS size
was unchanged. No background traffic collector or persistent traffic log was added.

## Reproduce and interpret

Follow the [English](docs/en.md), [Spanish](docs/es.md) or [Portuguese](docs/pt.md)
guide in an authorized disposable Debian VM with a recovery snapshot. Use the
documented supervisor probes and lifecycle commands. Repeat the transaction
sequence through each surface, record generation/revision identity, sample traffic
before and after probes, and compare the same stream/sequence across interfaces.
Preserve the journal and reports before cleanup. Do not commit credentials, raw
laboratory evidence or private operational data.

Native policy coverage here uses IPv4 and two explicit rules. The original
[validation report](VALIDATION.md) covers earlier failure-injection
and packet-policy tests. This run does not add evidence for VM reboot, power loss,
supervisor crash, sustained connection revocation, production MFA or capacity.
Native deletion/reordering and retention eviction were not repeated in this run;
unit/browser coverage must not be represented as native coverage. The bounded
512-record traffic history is sampled on request, ends with the API process and
does not include default-policy drops or connection details. A new stream rejects
old cursors with `ANDEIVA_TRAFFIC_STREAM_CHANGED`.

The scoped laboratory workflow is verified. Production authentication, resilient
appliance lifecycle and the untested failure/performance cases remain separate
work. Integration still requires review and successful checks on the final PR
commit. No release, public visibility change or new security engine is included.

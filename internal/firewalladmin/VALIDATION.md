# Administrative firewall laboratory validation

Implementation revision: `68e64c07b40ef6ad49ac80d94ca13f9096c260d6`.
Execution date: 2026-11-10 UTC. Environment: authorized Debian 13 AMD64 VM,
2 vCPU, 4 GiB RAM, three disposable network namespaces. Private credentials,
host identifiers, journals and diagnostic artifacts are excluded from Git.

## Observed behavior

| Scenario | Evidence and result |
|---|---|
| Web creation and activation | Actual browser over verified TLS; two typed rules staged, validated, committed with confirmation and explicitly confirmed. Running/readback hashes matched; Startup stayed unchanged. Repeated against the final binary. |
| Traffic | Real TCP and UDP echo accepted on allowed ports; another port, empty policy, narrowed source ports and unsolicited reverse connections denied. Historical rollback restored allowed traffic. |
| Surface parity | Web, CLI and HTTPS API observed the same canonical revision. CLI save and historical rollback succeeded. Audit distinguished Web, CLI and API operations. |
| Authorization | Anonymous reads and viewer writes/history denied; invalid rule data did not publish a revision. Runtime could not read operator credentials; operator could not read runtime key/state/account digests. |
| Concurrency | Two administrators staged from the same generation: one succeeded and the other received conflict. No partial candidate was published. |
| API loss | A pending 30-second commit reverted through the independent helper while the API was stopped. Restart reconciled the journal. No-op pending restart also recovered. An externally killed API was detected and could restart directly. |
| Helper loss | Supervisor closed API and removed its owned namespace/process resources. This expected failure produced an error report with cleanup and host invariance verified. |
| Startup persistence | Complete laboratory restart restored explicitly saved Startup, replacing an unsaved Running policy. This is a process/laboratory restart, not a VM reboot or power-loss test. |
| Final repeat | Final binary created and confirmed two additional rules through Web, passed six TCP/UDP forward/reverse probes, and stopped with checked cleanup. |
| Appearance | Real Light/Dark desktop/mobile screenshots retained privately; official logo hash unchanged. Separate CI browser tests cover fixtures, accessibility and EN/ES/PT. |

Host routes, ruleset and namespace inventory were compared before/after. Address
comparison excludes only DHCP preferred/valid lifetime counters, which change
with time and renewal; addresses, interfaces and all remaining fields match.
The fixture also checks its own stable host snapshot and unrelated sentinel.
SSH remained active and host forwarding remained disabled.

## Resource observations

These are bounded laboratory observations, not throughput or appliance capacity claims.

| Run | Wall time | Supervisor CPU | Children CPU | Largest child peak RSS |
|---|---:|---:|---:|---:|
| Interactive failure scenarios | 425.612 s | 0.111 s | 2.877 s | 21,332 KiB |
| Startup/API crash recovery | 367.512 s | 0.053 s | 0.551 s | 19,536 KiB |
| Final binary Web/traffic repeat | 57.447 s | 0.041 s | 0.609 s | 19,096 KiB |
| Explicit Deny priority and CLI rollback | 91.110 s | 0.032 s | 0.515 s | 16,672 KiB |

Wall times include operator pauses. Child peak RSS is the largest observed child,
not the sum of simultaneously resident processes. A live sample measured API RSS
20,660 KiB and helper RSS 20,224 KiB; two traffic listeners used 12,188/12,068 KiB.
The retained journal directory occupied 214,759 bytes after these four runs.
The browser renderer sampled separately used about 5.6 MB JavaScript heap in the
first run; that is neither total browser RSS nor appliance RAM.

Final supervisor SHA-256:
`9d888b3649ca3d70a85e9b9d5a0b871db95c3dc890c7d7819f10af7c999cfc67`.
Final CLI SHA-256:
`7365f2b8b2d5902d64ec32d8de3d9b682df0d731f14fcbb2985ccdf8e369a7ef`.
The first two runs used the preceding build before directory access was confined
with `os.Root` and overload errors gained correlation IDs; the final repeat used
the exact implementation revision above. No network-rule semantics changed between them.
Binary/run association is based on observed build and execution commands plus
separately captured installed hashes; the supervisor reports are not signed attestations.

A subsequent focused CLI check confirmed an explicit `confirm --target` revision
over the same verified HTTPS laboratory service. Its regression also rejects a
mismatched target without replacing it with Running. Import grouping and explicit
JSON serialization error handling were cleaned up without changing valid generated
rules. Managed status already returns before mutation-only validation; that path
was verified without changing its authorization contract.

## Automated coverage and remaining limits

Windows unit tests and Linux race/vet/platform builds passed. The 81 browser cases
include 27 firewall cases; these use controlled responses and are separate from
the real-browser runs above. Security analysis has narrowly reviewed local CLI
file-read and fixed privilege-dropper exceptions. Shared CI never starts the
privileged namespace fixture. Exact-head CI results are reported in the PR.

Four injected journal failures cover immediate and explicit confirmation followed
by failure before persistence or after rename. Compensation restores the previous
effective policy and blocks writes. A durable target left after rename is not
silently republished: API restart can remain blocked. Preserve the journal and
perform an explicit complete laboratory restart from saved Startup; unsaved
changes are not promised to survive that recovery path.

The tests do not establish production authentication/MFA, whole-supervisor crash
recovery, VM power-loss resistance, long-lived connection revocation under native
load, hostile local root resistance, throughput, IPv6 administration or application
inspection. Rule order and stateful tuple/mark constraints have structural and
negative tests; sustained conntrack revocation remains a separate native gate.
This flow does not activate the host firewall or implement NAT, VPN, IPS, antivirus,
WAF or proxy services. It is ready for review as an isolated experiment, not as a
production firewall.

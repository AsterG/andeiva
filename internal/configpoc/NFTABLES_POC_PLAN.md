# Proposed nftables transaction experiment

Status: design proposal only. No real-engine adapter, privileged helper, namespace
setup or traffic test is implemented or executed by this document. Approval of
this proposal would authorize a bounded laboratory implementation, not a working
appliance firewall or closure of the full configuration release gate.

## Objective and boundaries

Replace one simulated component with a real nftables adapter in an isolated Debian
13 amd64 laboratory VM. Demonstrate validation, one-batch activation, observed
state, compensating rollback and actual permitted/denied traffic. Retain the
existing Candidate/Running/Startup, concurrency, idempotency and audit principles.

No Windows/VPN changes, physical interface movement, host routing or forwarding
changes, management filtering, SSH changes, NAT, VPN, IPS, proxy, TLS inspection,
ISO or release publication. No daemon is installed into the ordinary appliance
startup path. Missing tools or kernel capabilities block the experiment; setup
must not silently install packages or change host policy.

## Contract approval before implementation

The current simulator schema contains ordered rule IDs and actions. It has no
packet selectors, interfaces, protocol semantics or privilege boundary. Do not
silently reinterpret its `allow` action as a real broad allow rule.

A separate versioned experiment contract must specify:

- A bounded fixture policy with explicit family, source/destination prefixes,
  protocol, service port, direction, ordered rules and default deny. Initial
  traffic cases may be IPv4-only; IPv6 compatibility must remain unclaimed until
  a separately defined dual-stack matrix passes.
- A deterministic compiler whose output identifies its schema/compiler version,
  logical revision, exact artifact digest and declared target. Arbitrary nft
  text, expressions, includes, filenames and shell fragments are not inputs.
- Node-local mapping from fixed logical fixture ports to test-owned interface
  identities. This mapping is separate from the shared policy digest.
- Acknowledgment of the exact applied revision plus a normalized observation of
  its actual kernel policy. A stored comment or an exit code alone is insufficient.
- Stable errors for validation, stale observation, helper denial, apply failure,
  uncertain outcome, drift and failed compensation. Audit includes actor, request
  ID, generation, artifact digest, namespace identity and observed outcome.
- Who may stage, commit, confirm, save, recover and inspect diagnostics. Production
  authentication, role names and public API changes require their own approval.

The first review must cover this schema, helper protocol and failure matrix before
code can expose a real-engine operation. Keep simulator schema compatibility and
existing tests intact. This proposal does not choose a production database.

## Isolated laboratory

Use three newly created network namespaces connected only to each other:

```text
test source -- private virtual link -- test gateway -- private virtual link -- test sink
                                       owned nft table
```

The setup supervisor owns all namespace handles, virtual interfaces, fixture
processes and a private run manifest. Create virtual links inside those namespaces;
never move a VM NIC or attach a fixture link to the VM's normal namespace, bridge,
NAT network or management interface. Addresses and routes exist only within the
fixture. Any forwarding setting is changed only after verifying the gateway
namespace identity. The namespaces must have no external default route.

Network namespaces isolate network devices, routes, firewall rules and sockets;
they are not separate kernels. This motivates isolation but does not prove that a
particular setup is correct. Verify namespace inode/handle identity at every
privileged boundary. [Linux network namespace documentation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)

Use one dedicated, fixed adapter table, such as `inet andeiva_poc`, inside the
gateway namespace. The setup harness may create a separate inert sentinel table
to prove the adapter leaves other tables unchanged. Refuse pre-existing fixture
names or unexpected objects; do not adopt or clear them.

Before mutation, verify the VM identity, Debian version, tools, kernel features,
authorized snapshot and recovery console. Record a private baseline of normal
namespace rules, routes, interface identities, forwarding settings and SSH health.
Keep the normal management connection outside all test namespaces. Test loss of
connectivity using a fixture service, never the real SSH or management endpoint.

## Narrow privilege boundary

The coordinator and traffic clients remain unprivileged. A short-lived setup
supervisor creates the isolated resources. A separate apply helper operates in
the pinned gateway namespace with only the capabilities demonstrated necessary.
Do not give the web/API process root, a shell, unrestricted sudo or arbitrary
`ip netns exec` access.

The helper protocol accepts fixed typed verbs for checking a prepared revision,
applying it, observing the owned table and restoring a previously verified revision.
Bind requests to the authorized local peer and the supervisor-issued run identity;
reject target namespace, table, path, command or executable selection by callers.
Use a bounded local channel with verified peer credentials and restricted ownership.
The helper independently validates the typed policy and generates only the allowed
batch; a caller's assertion that arbitrary input was already compiled is not trusted.
Responses bind the run identity, request ID, namespace identity, logical revision
and artifact digest. A late acknowledgment from an expired request or earlier
attempt cannot confirm a newer transaction or override a completed rollback.

For the initial adapter, a fixed verified nft executable with fixed argument arrays
and compiler-produced input through stdin is a proposed implementation. No shell,
environment-provided executable, external include, name resolution or user-supplied
program is permitted. Process duration, input/output sizes and concurrency are
bounded. Privileged setup/teardown is a separate test-only interface, unavailable
through configuration operations.

## Validate, activate and observe

1. Validate the typed policy and trusted target, compile deterministically and
   record the logical revision, compiler version and artifact digest.
2. Compare the actual owned table with the expected prior observation. Reject
   drift; do not silently overwrite another writer. Keep one cooperating writer
   for this table and treat privileged external modification as a detected fault,
   not something an advisory application lock can prevent.
3. Run nft validation in the pinned gateway namespace with `--check` and the exact
   prepared input. The option checks command validity without applying changes;
   it does not prove connectivity or reserve state against a later change.
   [Official nft manual](https://netfilter.org/projects/nftables/manpage.html)
4. Persist the transaction intent and its previous verified artifact before apply.
5. Submit a single batch containing the complete bounded replacement of the owned
   table. Do not run a flush and reconstruction as separate commands. Never use
   `flush ruleset`. Exact create/update syntax must be tested against the installed
   nft version; loading a table description repeatedly can append duplicate rules.
   [Official atomic replacement documentation](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)
6. Observe the table through numeric JSON output and normalize only known volatile
   fields, such as handles and counters. Preserve rule order, selectors, verdicts,
   hooks and chain policies in the comparison. Reject unknown expressions rather
   than removing them from the digest. Then run independent traffic assertions.
7. Publish Running and the durable receipt only after those observations succeed.
   An uncertain apply or lost response triggers observation/reconciliation, never
   an assumption that the kernel rejected the request.

One nft batch can provide a kernel transaction boundary; it does not atomically
commit the journal, another engine, identity state and traffic delivery together.
Compensation applies the exact previous verified artifact in another checked
batch, then verifies policy and traffic again. A failure to restore remains an
explicit recovery-required result and blocks further changes. Default deny must
not be relaxed to make connectivity checks pass.

## Confirmation and restart boundaries

Keep ordinary commit and explicit save separate. Controller restart must inspect
the surviving kernel table rather than recreate a blank simulated engine and
claim dataplane continuity. A simulated boot flag is not a real VM reboot.

Real commit-confirmed testing requires a rollback authority that outlives the
coordinator, holds the verified previous artifact and owns the deadline. Its
protocol, lease lifetime, peer-loss behavior and restart handling need explicit
review. Killing only the coordinator must not extend the confirmation window.
If killing that authority can leave a permissive provisional policy indefinitely,
record a failed/open gate; do not claim safe confirmed commits during that outage.
Do not enable provisional real allow policies until the defined failure model has
a demonstrated safe expiry path. No power-loss or physical reboot guarantee is
inferred from process termination or namespace deletion.

## Reproducible acceptance cases

Every case starts from an identified fixture and verified policy. Record expected
and observed results, monotonic timings, exit codes and exact artifact hashes.
Do not count an absent listener or broken route as proof of firewall denial.

| Case | Required evidence |
| --- | --- |
| Isolation | Normal namespace routes, interfaces, forwarding configuration and rules remain equivalent; management/SSH health unchanged |
| Baseline | Fixture service is healthy; default-denied traffic fails and a separately authorized positive control succeeds |
| Validation | Malformed/unsupported policy or invalid nft batch leaves the prior observed table and traffic behavior unchanged |
| Apply | One compiled revision changes only the owned table; normalized kernel policy matches it; both allow and deny cases behave as specified |
| Atomicity | Define a probe set denied by every revision; its continuous uniquely numbered probes produce zero successes across repeated replacement. This is bounded observation, not proof for all schedules |
| Rule order | Conflicting ordered fixture rules produce the approved first-match result; reordering changes both the content revision and observed behavior |
| Retry/conflict | Duplicate request cannot duplicate rules; stale generation or changed retry payload is rejected; concurrent admins cannot silently overwrite |
| Lost acknowledgment | Terminate the helper/controller around dispatch and receipt; restart observes actual kernel state and resolves the durable intent without inventing success |
| Rollback | Inject an apply/health failure; restore the previous table and verify positive and negative traffic, including the component that may have changed before returning failure |
| Recovery failure | Failed compensation remains blocked and cannot publish a healthy Running revision or discard the rollback target |
| Controller outage | Stable kernel policy remains effective while the coordinator is absent; a provisional commit follows the independently reviewed expiry contract |
| Drift | Unexpected rule/table mutation is detected and stops new commits; sentinel objects remain unchanged |
| State | Save affects Startup explicitly; process recovery preserves audit/revocations; actual boot tests are separate and remain pending until executed |
| Authorization | All adapter entry points use the same typed operation, validation and service authorization; unauthorized callers cannot reach privileged actions |
| Cleanup | Only run-owned processes, table, links and namespaces are removed; no fixture remains and the normal namespace baseline still matches |

Use new short-lived connections and unique tuples for traffic assertions so an
existing connection cannot hide a changed policy. Add established-connection
behavior only through an explicit stateful-policy contract. Keep observers outside
the coordinator so a crashed controller cannot fabricate their outcome.

## Resources, evidence and teardown

Before execution, approve a small fixed workload and budgets for commit/check/
readback/rollback duration, CPU, RSS, journal growth, subprocess count, probe rate
and total experiment duration. Measure a warm-up followed by repeated fresh
fixtures. Report p50/p95 and ranges with sample counts; do not extrapolate these
results to production throughput or hardware capacity.

Keep privileged diagnostics and lab addresses in private evidence. Public results
may summarize the tested source revision, fixture, pass/fail and limitations.
Record the installed nft/kernel capabilities privately instead of assuming the
latest online documentation exactly matches the lab.

Teardown must use the run manifest and retained namespace identities. Stop only
owned fixture processes, remove only owned resources and verify their absence.
Do not use global namespace deletion, broad process killing or a host ruleset
flush. A namespace can remain alive while processes or handles still reference it,
so deletion of its name is not sufficient cleanup evidence.
[iproute2 namespace lifecycle documentation](https://man7.org/linux/man-pages/man8/ip-netns.8.html)

If ownership or namespace identity is uncertain, stop and preserve diagnostics.
Use the authorized local console/snapshot recovery procedure rather than changing
corporate routes or relaxing firewall defaults. This experiment does not validate
NAT, inspection engines, HA, production authentication, signed updates, physical
power loss, or the complete firewall product. Planning is not execution evidence.

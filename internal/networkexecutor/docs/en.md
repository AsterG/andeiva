# Static IPv4 namespace executor — NET-EXECUTOR-001

`ObservedSnapshot` captures actual empty-IPv4 inventory without a desired plan or
PlanHash. PrepareObserved accepts only supervisor-authenticated physical bindings;
it performs no address/route writes and creates no transaction. VerifyObserved
checks the actual baseline. RecoverObserved also requires the original immutable
namespace identity retained only by NewInOwnedNamespace. It never grants L3
ownership. ObservedMatchesPrepared compares every physical fact when a subsequent
real desired plan is supplied; equality is not authorization. The initial profile
is exactly two owned links plus optional loopback, with no IPv4 addresses/routes.
Existing configured interfaces and DHCP leases remain outside this helper profile.

Owner: network executor. Status: isolated qualification verified; PR/integration
pending. The isolated routing laboratory consumes this package; appliance API, CLI,
runtime and privileged helpers do not.

`New(supervisorLifetime, trustedNamespaceFD)` duplicates and pins a Linux network
namespace descriptor, checks namespace type and rejects the current and PID 1
network namespaces. The privileged supervisor must start in the host namespace,
own all writers in the disposable namespace, and keep its recovery context alive
until `Restore` completes. This authority must never come from an HTTP caller.
The process permits one owner per namespace; external exclusivity remains the
supervisor's responsibility. A process crash loses the in-memory recovery plan.

`NewWithHost(supervisorLifetime, targetFD, trustedHostFD)` supports a service
manager opening the host anchor before restricting privileges. Both descriptors
are duplicated and validated as nsfs network namespaces; host must equal the
supervisor's current namespace and target must differ. Closing caller descriptors
does not invalidate the owned pins. Trusted service assembly must establish host
provenance; an inode alone cannot prove it. Never obtain this capability from HTTP,
untrusted IPC or arbitrary descriptor/path input. `New` retains the default
`/proc/1/ns/net` anchor check and fails if that path is inaccessible; no additional
capability or weakened host guard is introduced to bypass such failure.

`Apply` accepts a canonical `networkplan.Revision` with static IPv4, DNS mode
`none`, and ordinary subnets with prefix lengths 1–30. Every link must initially
have zero IPv4 addresses and every IPv4 route table must be empty, including
loopback/local routes. Links must already have the required administrative state.
Existing-address migration (including management LAN migration), DHCP lifecycle,
DNS, link state, policy routing, IPv6, NAT, firewall, sysctls, VPN and host networking
are unsupported. This is not an appliance network manager.

Only fixed `/usr/bin/nsenter` and `/usr/bin/ip` commands run, with the namespace
in inherited FD 3, a fixed environment, root-owned non-writable executable paths,
two-second command deadlines and 256 KiB output limits per stream. There is no
shell, arbitrary command/path input, installation, listener or permanent worker.
The threat model assumes trusted root/kernel/executable installation and exclusive
namespace ownership; it does not defend against another hostile root process.

Before effects, trusted namespace observations are bound through `networkplan.Bind`.
Each sample joins IPv4 address records to name/index/MAC identities from two
matching `ip -j link show` observations. The IPv4 selector omits MACs and links
without IPv4; an empty address response does not imply an empty link inventory.
Link identity is checked again before each mutation and during final semantic
readback. All controlled IPv4 addresses and all route tables must match the plan,
including kernel-derived connected/local routes. Unknown route/address attributes
are rejected. This neither proves reachability nor enables forwarding/inspection.
Duplicate JSON member names are rejected with exact JSON name semantics.
Unknown traffic is never released for evidence or granted an inspection bypass.
`Verify` repeats this read-only check for the active plan; drift or unavailable
readback fences the instance without attempting further network changes.

Call `Restore` before `Close`. Compensation uses the supervisor lifetime rather
than the request context, removes only exact attempted additions, and verifies the
original controlled snapshot. Identity change, command failure or mismatched
restoration permanently fences the instance. Link identity is rechecked before
every deletion; these checks are not
atomic against a foreign writer with CAP_NET_ADMIN, which ownership excludes.
Do not retry admission through a new instance: retain evidence and destroy only
the supervisor-owned disposable fixture.
`Close` only releases the descriptor; it does not claim restoration or durability.

Rollback of this source-only change: leave the package unconnected or revert its
commit. No persistent format, service or host configuration has changed.

Tests (Go 1.27.4, Linux/WSL; no privileges/network mutations required):

```sh
go test -race ./internal/networkexecutor ./internal/networkplan ./internal/networkinventory
go vet ./internal/networkexecutor
go build ./internal/networkexecutor
GOOS=linux GOARCH=arm64 go build ./internal/networkexecutor
GOOS=windows GOARCH=amd64 go build ./internal/networkexecutor
GOOS=darwin GOARCH=arm64 go build ./internal/networkexecutor
```

Tests use simulated command results plus read-only namespace checks. Independent
root and architecture review of source `460fece` found no critical/high/moderate
findings; the independent race repeat (`-count=3`) passed in 1.647 s.

Debian 13 amd64 qualification of source `460fece` (binary SHA-256 prefix
`590a4005`) passed the three-namespace runner: typed apply/readback/restoration,
TCP/UDP SNAT with real conntrack tuples, related ICMP, IPv6 denial, unsolicited
reverse denial, existing TCP revocation, routing without NAT, and proof that NAT
does not authorize forwarding. Namespace cleanup and outer host invariants passed.
The helper had only SYS_ADMIN/NET_ADMIN and a supervisor-provided host FD 0;
the root supervisor loaded the prerequisite conntrack module separately.
Measured elapsed 4.408428 s, CPU 1.116154 s, peak 32,321,536 bytes for this single
fixture run. These are not appliance throughput/capacity benchmarks.

Existing management LAN migration, DHCP, appliance runtime activation and durable
crash recovery remain unsupported. Container execution and appliance resource
budgets remain unqualified. No Docker/EKS/Helm integration or release/milestone
completion is claimed. See the routing runner's EN/ES/PT guides for prerequisites.

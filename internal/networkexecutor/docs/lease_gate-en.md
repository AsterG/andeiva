# Isolated DHCP authority gate

This experimental library restricts WAN forwarding in an exclusively owned,
non-host namespace. It is not wired into appliance activation or recovery. No
host interface, route, DNS setting, firewall or power-management setting changes.
Native kernel/packet qualification and resource measurements remain pending.

The trusted supervisor supplies namespace descriptors, helper identity, canonical
DHCP WAN/static LAN plan and one authenticated lease owner. The helper retains
only NET_ADMIN, no_new_privs and its approved groups. The constructor only reads
and pins resources. A separate gate ownership registry permits coexistence with
LeaseExecutor while refusing a second gate instance in the same process/namespace.

`LeaseGateAuthority.Current` returns the current lease and selected-work digest.
`Verify` must independently verify the exact selected work/reserve, L3 delta,
unchanged LAN baseline, firewall policy, interface identity and absence of
offload. The digest alone is never permission. These callbacks are trusted
assembly capabilities; no JSON endpoint or arbitrary command interface is added.
Assembly must serialize policy/authority changes with the gate operations.

Use this sequence:

1. `Initialize` creates the absent fixed table `inet andeiva_lease_gate`, closed.
   An existing table is refused, never adopted or replaced.
2. `Close` removes both the enable element and lease token, then verifies the
   complete table. Turn namespace IPv4/IPv6 forwarding off and verify it.
3. Apply/verify LeaseExecutor changes and the required policy/selected work.
4. `Stage` verifies that forwarding remains off, obtains current authority and
   installs one temporary token while the gate is closed. A sequence is consumed
   before mutation. Lost ACK is resolved by readback, without recreating a token.
5. `Open` rechecks authority and changes only the enable set. It never recreates
   or extends the temporary token. It does not turn IP forwarding on.
6. A subsequent grant requires Close and a fresh sequence. Revocation, failure,
   withdrawal and Confirm/rollback must never restore an old token.

The fixed forward base chain has priority -300 and DROP rules for both WAN
directions, including established connections. WAN IPv6 is dropped. The gate
contains no accept rule, conntrack exemption, dynamic-set update or flowtable.
Its base-chain accept policy merely continues to the mandatory firewall policy;
it is not a replacement policy. The trusted assembly must prohibit forwarding
offload and preserve exclusive writer ownership.

The parser checks the full table, set definitions, rule order and expressions.
It rejects extra objects, permanent tokens, missing expiry, overflow, duplicate
JSON fields and changed semantics. Readback is timestamped with CLOCK_BOOTTIME
after receipt. The reported remaining whole seconds plus a one-second rounding
allowance must fit before the original lease deadline. Stage reserves two seconds
before insertion, but this estimate alone never authorizes opening: delayed
kernel insertion or readback must pass the post-receipt check.

`ErrLeaseGateUncertain` means closure was not proven. It requires the independent
supervisor to disable forwarding or tear down its namespace. Do not report a
restored baseline or release traffic on this error. A failure fences the instance;
there is no restart adoption, durable ownership journal or recovered token here.
The existing selected-work/R2 recovery boundary remains a separate dependency.

The [libnftables JSON contract](https://manpages.debian.org/trixie/libnftables1/libnftables-json.5.en.html)
expresses timeout in seconds. Linux 6.12 [set expiry uses jiffies](https://github.com/torvalds/linux/blob/v6.12/include/net/netfilter/nf_tables.h).
This cut is limited to continuous execution. Suspend, VM pause/snapshot restore,
clock-profile qualification and expiry during those conditions are not supported
or proven. No power-management mitigation is installed.

Unprivileged Linux/WSL checks:

```sh
go test -race ./internal/networkexecutor -run '^TestLeaseGate' -count=1
go vet ./internal/networkexecutor
go build ./internal/networkexecutor
go test -c -o lease-gate-native.test ./internal/networkexecutor
```

Unit tests use explicit kernel doubles and qualify state-machine/readback
negatives only. They are not evidence of native nft syntax, packet filtering,
expiry after helper death or hardware timing. The next authorized Debian test
must reuse the isolated namespace/helper profile, verify real JSON timeout units
and remaining time, both traffic directions including established connections,
helper pause/death, delayed ACK, exact LAN preservation, host dual-stack invariants
and teardown. No privileged WSL/shared-CI run is authorized by these commands.
No Docker/Helm service, dependency or shared coordinator DTO changes in this cut.

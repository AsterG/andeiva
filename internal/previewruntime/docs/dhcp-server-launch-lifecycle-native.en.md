# LAN DHCP launcher lifecycle qualification

On 2026-11-18 the isolated Debian 13 fixture passed in 8.15 s. The test covered
launch and disable of the LAN component with the WAN slot empty. It left zero
owned processes and sockets before supervisor exit, unchanged firewall rules,
no active generated configuration and the same lease file inventory and content.
Selected transactions and DORA/RENEW qualification remain separate.

The test unit used 0.387 CPU seconds and peaked at 44,118,016 bytes. Its parent
cgroup used 42,840,064 bytes at the end of the enabled window and 34,959,360
bytes at the end of the disabled window. The enabled component consumed 199
microseconds of CPU between the two enabled samples. Its CPU counter stayed
constant across the two disabled samples. These figures describe the fixture.
The result SHA256 is `ad7b79085ddbb30f3196cfbcc61198475225f578c4ba9c4fffdebb20128d922b`.

The fixed launcher and sealed role are exercised with an isolated gateway and
the exact two-slot service set. WAN stays empty. Real Kea readiness requires the
dedicated account, exact capabilities, enforced stock AppArmor, original parent
and retained pidfd/start identity, and an owned AF_PACKET socket on the observed
LAN ifindex. A launch handle alone is insufficient.

ADR-075 replaces the private launcher wire with version2. The trusted parent
prepares exactly two detached mount trees from the existing configuration and
operational lease descriptors before creating the child mount namespace. The
child validates all inherited slots with raw syscalls before creating pollable
files: FD3–9 retain their meanings, FD10/11 carry configuration/lease trees and
FD12/13 carry the exact cgroup pins. The sealed bootstrap binds ordered source
identities and parent provenance; obsolete or malformed peers are rejected.
Configuration is read-only, leases remain read/write on their original inodes,
and both mounts enforce nosuid/nodev/noexec before and after transfer. There is
no pathname fallback, operational-store copy for transfer, capability increase
or production dispatcher activation. Existing bounded private LFC validation
copies remain mandatory; the serving mount retains the original operational
directory. The standalone kernel reproducer passed; full lifecycle acceptance
and the resource delta for this component remain pending.

Disable is checked **while the supervisor still runs**: Stop and leaf drainage,
dead retained pidfds, no remaining LAN/WAN leaf members, no UDP/RAW/PACKET/UNIX
sockets, unchanged closed rules, no process/observer retaining the private
configuration mount, and removed generated runtime input. Operational lease
files are retained and must not change during the disabled sample. Empty slot
inodes remain stable until whole-incarnation retirement; no zero-cgroup or
zero-kernel-cost claim is made.

Resource samples cover before/after infrastructure and two four-second windows
while enabled and disabled. They record actual BOOTTIME, CPU counters, per-PID
RSS/PSS and parent memory.current/peak/stat. Parent data includes the harness and
shared infrastructure and must not be reported as Kea-only cost. Controllers
are never enabled for measurement. A missing required counter fails the fixture
instead of fabricating a value: each parent/leaf CPU sample requires
`usage_usec`, `user_usec` and `system_usec`. Additional CPU fields are optional;
an absent leaf in before/after-infrastructure phases has `own_cpu:null` and
supplies no leaf CPU measurement. The JSON does not establish a sizing target.

## Developer checks

Run unprivileged in the prepared offline development image, with source mounted
read-only:

```sh
go test -race ./internal/previewruntime -run '^TestRoutedDHCPServer' -count=1
go vet ./internal/previewruntime
go test -c ./internal/previewruntime -o /tmp/kea-lifecycle-native.test
bash -n packaging/preview/tests/dhcp-server-launch-lifecycle-native.sh
```

The native test skips without its explicit opt-in. A skip is not native evidence.
Default, CI and non-root script invocations must refuse before mutations.

## Isolated Debian qualification

Root alone schedules execution on an authorized Debian13 test VM with snapshot
and console. Never run on Windows/WSL, a customer appliance, or concurrently with
another qualification. Kea and its offline dependencies must already be present;
the stock service must remain masked/inactive. Stock AppArmor must enforce. The
test binary and driver must be root-owned, without writable ancestors, aliases,
hardlinks or ACLs. Use a trusted artifact directory; do not copy arbitrary files
into executable product paths.

After independently reviewing the binary/script hashes, the root orchestrator
may create the otherwise absent, fixed **transient laboratory** unit:

```sh
systemd-run --unit=andeiva-preview-grouped.service \
  --property=Type=exec --property=RemainAfterExit=yes \
  --property=User=root --property=Group=root --property=Restart=no \
  --property=KillMode=control-group --property=Delegate=no \
  --property=NoNewPrivileges=yes --property=RuntimeMaxSec=160s \
  --property=TimeoutStopSec=15s --property=MemoryMax=256M \
  --property=TasksMax=64 --property=CPUQuota=100% \
  --property=CPUAccounting=yes --property=MemoryAccounting=yes \
  --property=LimitNOFILE=256 --property=LimitFSIZE=64M \
  --property=LogRateLimitIntervalSec=30s --property=LogRateLimitBurst=1000 \
  --setenv=ANDEIVA_KEA_LIFECYCLE_AUTHORIZED=1 \
  /bin/bash /ROOT_REVIEWED_DIRECTORY/dhcp-server-launch-lifecycle-native.sh \
  --isolated-lab /ROOT_REVIEWED_DIRECTORY/kea-lifecycle-native.test
```

Replace the two explicit placeholders with the reviewed root-protected paths.
This full-root laboratory bootstrap is not production privilege evidence.
The unit's 64 MiB file limit is only the artifact-copy budget (the reviewed
binary is larger than 8 MiB; input remains bounded to 64 MiB). After copying,
chmod, fixture-directory creation and hashes, the driver unsets
`POSIXLY_CORRECT`, disables Bash POSIX mode, and sets both soft/hard runtime file
limits with `ulimit -S -f 8192` and `ulimit -H -f 8192`. In that mode Bash uses
1024-byte blocks: 8192 means exactly 8,388,608 bytes. The driver verifies both
kernel limits and the `bytes` unit in `/proc/self/limits` before snapshots or
unshare. Runtime children inherit this 8 MiB soft/hard cap, including when
the caller originally supplied `POSIXLY_CORRECT=1`. No product limit changes.
Capture the exact InvocationID, exit status, evidence path and accounting before
stopping only that same invocation. Require FD store empty, no surviving service
leaf/processes and a matching unit identity. Do not reset failed units or delete
uncertain resources to make a test pass.

Evidence is preserved in a fresh protected `/var/backups/andeiva-kea-lifecycle.*`
directory: lifecycle-result.json, observations, artifact hashes, host invariants,
namespace cleanup and unit accounting. Host comparison excludes only ageing
address/route lifetimes, nft version metadata and packet-counter values, as in the
existing native driver; functional addresses/routes/rules/forwarding and host
mounts must match. Failures retain evidence and rely on the containing unit for
drainage. No package installation, service unmasking, host network mutation or
automatic cleanup of evidence is performed.

Translations: [Español](dhcp-server-launch-lifecycle-native.es.md),
[Português](dhcp-server-launch-lifecycle-native.pt.md).

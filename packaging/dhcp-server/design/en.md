# TP-DHCP-LAN-001 — Offline DHCPv4 server packaging

Owner: backend/control plane. Date: 2026-11-13. Status: **proposal, not selected,
implemented, installed or qualified**. Base: main `ca4afb2`; configuration contract:
PR70 `dee8c1b` plus boundary tests `06d6c67`. No runtime/API contract is changed.
[Español](es.md) · [Português](pt.md) · [dependency evidence](evidence.md).

## Decision proposed for an ADR

Evaluate Debian 13's `kea-dhcp4-server` component, exact-version `kea-common`, and
the complete verified dependency closure. Use persistent memfile for the first
bounded laboratory evaluation, with no database server, commercial hook, DDNS,
DHCPv6, HA, relay or control-agent daemon. This is a recommendation for evaluation,
not permission to ship memfile before durability and resource gates pass.

| Option | Consequence |
|---|---|
| Keep PR70 validation only | Lowest runtime risk; no functioning LAN DHCP server. Current state. |
| Kea DHCPv4 component | Existing technology candidate; separates serving from management. Requires native raw-socket fencing, durability and dependency review. Recommended evaluation. |
| dnsmasq | Existing footprint comparator only. Requires independent option/reservation parity, isolation and persistence evidence; no assumed performance advantage. |

Follow the existing technology-change process and ADR-033's no-HA-v1 boundary.
Do not reinterpret WAN client ADR-050/058 as server authorization. Architecture,
security, licensing and performance reviews precede an approved numbered ADR and
implementation. Preserve PR70's 32 scopes, 65,536 declared pool addresses,
exclusions, reservations, selected LAN binding and `T1 < T2 < lease`; engine
constraints may reject enablement explicitly, never silently reduce the contract.

## Offline input and installation boundary

The [evidence](evidence.md) verifies 51 dependency packages per architecture,
94 distinct archives across amd64/arm64, against signed Debian metadata. It is
not an installable minimal OS or a signed ANDEIVA update. Essential base packages,
systemd, AppArmor and the actual target dpkg status are separate prerequisites.
Client libraries for MariaDB/PostgreSQL remain dependencies with memfile; exclude
their servers. Do not use the `kea` metapackage, Recommends, online apt, or a
customer-side resolver that silently substitutes versions.

Reuse the existing offline builder/verifier trust model, not its boot-specific
installer. On the build host, resolve from a pinned, signed repository snapshot
against an authenticated target baseline. Capture every Depends/Pre-Depends
alternative, package/source version, architecture, archive size/hash, metadata,
source availability, licenses and SBOM. The install manifest also binds the exact
transaction delta and baseline status hash. Re-resolve when the baseline changes;
do not downgrade newer dependencies or upgrade libc/SSL as a side effect. An
explicitly reviewed OS update is a different transaction.

At the appliance, verify trusted ANDEIVA signatures, Debian provenance, time,
architecture, free space/inodes, backup and exact delta before effects. Simulate
with **only local inputs**, `--no-download --no-install-recommends --no-remove`;
compare the entire action list with the manifest. Preserve signature/expiry
checks; neither `trusted=yes` nor `--allow-unauthenticated` is acceptable. APT's
simulation alone does not prove cached archive availability: verify all hashes
and run the download-only/no-download cache check before entering dpkg.

## Prevent package activation

Reviewed Debian scripts attempt enable/start/restart, account/config ownership
changes and AppArmor reload. Therefore `policy-rc.d` alone is insufficient.

1. Serialize package management and feature transitions; journal and sync the
   planned delta, unit policy, configuration and preservation inventory. Reject a
   foreign/pre-existing server, user conflict, unit override or lease directory;
   do not adopt, stop or overwrite unrelated services.
2. Before unpack/configure, create and verify an **owned persistent mask** of the
   stock `kea-dhcp4-server.service`; retain it across reboot. The reviewed product
   launcher, not that stock unit, will own the future selected service. Verify
   maintainer-script unmask/enable paths cannot defeat this mask.
3. Run approved maintainer scripts in a private mount namespace with an immutable
   scoped `policy-rc.d` view denying activation of the reviewed Kea units. Delegate
   unrelated requests to the unchanged existing policy; fail if this cannot be
   preserved. If the path is absent, provide it through a private directory view,
   not a temporary host-file replacement. Retain original identity/hash and prove
   the parent mount view is unchanged. Do not rely on PATH or environment tricks.
4. Review **all** delta maintainer scripts and triggers. Account changes, ldconfig,
   AppArmor and daemon-reload are real effects, not prevented by the start policy.
   Permit only the reviewed effects; unknown/direct daemon execution blocks the
   package. No blanket AppArmor disablement or success after parser failure.
5. Verify the persistent mask, unit enablement state, no DHCP process/LFC child,
   packet/raw/UDP socket or DHCP reply before completing install. Interruption
   retains the mask and recovery journal; generic `apt -f install` is not recovery.

## Runtime, data and resource design

The API/CLI/web only submit validated candidate configuration through the existing
RBAC/audit/coordinator. Running changes after verified activation and confirmation;
Startup changes only on Save. No caller-supplied executable, engine JSON, path,
namespace or privilege. Lease data is operational engine state, not another
configuration database. Normal administrative responses omit engine/version and
privileged diagnostics.

Use one service identity distinct from API/helper, a pinned owned namespace and
explicit selected LAN interfaces, never `*`, host or WAN. Review the packaged
NET_RAW/NET_BIND_SERVICE requirements without adding them to API/helper. Kea's
direct-client raw path bypasses IP filtering; an INPUT rule alone is **not** a
DHCP fence. Kernel-enforced confinement/withdrawal before replies, interface
replacement, process death and namespace drainage require native proof. No raw
fallback or relaxed readiness to make enablement pass. See the
[versioned Kea socket documentation](https://kea.readthedocs.io/en/kea-2.6.3/arm/dhcp4-srv.html#interface-configuration).
The interface allowlist also does not prevent a compromised NET_RAW process from
opening another link in the same namespace. Do not put this worker beside WAN
without a reviewed enforced boundary; any new LAN-only namespace topology needs
separate approval, not an implicit packaging change.

Disabled means no serving process, LFC child, raw/UDP/control socket, timer,
exclusive worker or generated rule/config active. Keep dormant candidate/state
data. Drain the entire owned service cgroup, verify descriptors/listeners and
owned policy removal; a stop request or empty UDP `ss` result is insufficient.
Do not delete the core audit or alter forwarding/NAT when disabling DHCP.

Proposed storage acceptance uses a dedicated quota and reservation, including
live lease files, all [LFC intermediate files](https://kea.readthedocs.io/en/kea-2.6.3/arm/lfc.html),
append growth during worst cleanup latency, temporary configuration and retained
upgrade recovery. A preliminary **512 MiB active-data cap plus 512 MiB recovery
reservation** is a measurement target, not a proven capacity. Admit a scope only
if measured worst-case row size/churn/cleanup copies fit; 65,536 leases must be
tested independently. Do not rotate/truncate the authoritative lease file as a
log. Bound diagnostic logs separately; protected audit follows the existing
Storage Manager contract. At the precomputed high-water mark, safely stop new
allocation/renewal before durability becomes uncertain; prove this engine boundary
or block selection. ENOSPC, inode exhaustion and malformed lease rows must not
cause empty-database startup or forgotten ownership.

Memfile persistence does not by itself prove durable ACK-before-crash ordering.
That is a release blocker. Measure ACK/fsync/power-loss behavior and clock rollback;
if incompatible, propose a reviewed backend change rather than claiming safety.
CPU/RSS/PSS, LFC peak, startup, write amplification and disable-to-zero timings are
pending on 2 GiB hardware and both architectures. No performance claim is made.

## Upgrade, removal and rollback

Quiesce through a durable selected operation before package changes. Stop serving
and LFC, verify drainage, sync and snapshot the **complete** lease state plus
compiler/engine versions and audit references. Never purge leases or audit from
maintainer scripts, remove, autoremove or rollback. Retain ANDEIVA-owned data
separately from package defaults; align permissions/AppArmor in a reviewed change.
Remove only the manifest-owned package delta with no foreign reverse dependency;
otherwise keep dormant dependencies. Reinstallation must find preserved data.

Rollback of configuration or binaries must retain leases issued since the old
configuration; restoring an old lease snapshot can cause duplicate allocation.
Test older-engine readability of the latest data before allowing binary downgrade.
Otherwise remain disabled with recoverable state. Shrinking/moving a scope must
retain ownership until the original lease expiry or verified release; no second
authoritative lease store. Crash recovery resumes the same operation and original
deadline. Changes to this coordinator/lease contract need their own approved ADR.

## Acceptance gates — future native tests, not executed

| ID | Injection/setup | Required result/evidence |
|---|---|---|
| PKG-01 | Minimal Debian13 amd64 and arm64, no engine, egress physically disconnected | Exact local delta installs; no download attempt, process, raw/UDP socket or reply before enable. Capture dpkg/unit/policy/AppArmor/host-network before/after. |
| PKG-02 | Missing/corrupt/wrong-arch package, forged/expired metadata, changed target status | Refuse before unpack; zero package/runtime changes. |
| PKG-03 | Existing custom policy, absent policy, restrictive umask, foreign engine/unit/state | Preserve policy behavior and bytes; refuse foreign ownership; no implicit takeover. |
| PKG-04 | Kill installer after mask, unpack, configure, enable attempt and journal sync; reboot | Stock unit never starts; retained journal resumes exact transaction or blocks; no generic repair. |
| RUN-01 | Real isolated LAN clients, at least two scopes, WAN capture | DORA/renew/expiry and PR70 options; no WAN/host reply, excluded/router address or reservation collision. Reservation outside pool works. |
| RUN-02 | Disable with active leases and LFC, then reboot/re-enable | Zero exclusive runtime after drainage; retained lease ownership, no duplicate allocation. |
| RUN-03 | Raw-socket traffic while withdrawing policy, changing link identity, killing worker | Independent fence stops replies; IP firewall-only false positives rejected. |
| DATA-01 | Quota/inode exhaustion, read-only data, short write, corrupt row, kill each LFC rename | No ACK without recoverable ownership, no empty fallback; protected audit/recovery preserved. |
| DATA-02 | Power cut immediately after ACK; wall clock backwards/forwards | No address reissued before valid expiry/release; measured durability and time contract. |
| UP-01 | Enabled/disabled upgrade, interrupted upgrade, backward-incompatible latest leases | States retained; incompatible rollback blocks; all issued leases/audit remain. |
| RM-01 | Remove/reinstall, foreign reverse dependency, purge request | No lease/audit deletion, no unrelated package removal, explicit purge refusal. |
| RES-01 | 1/32 scopes, 1/65,536 leases, churn/flood, LFC, 24h soak; disabled baseline | Record PSS/RSS/CPU/disk/inodes/latency and zero disabled delta. Budget/independent review before selection. |

All runtime gates use an authorized disposable lab with recovery snapshot and
independent host invariants. No VM, package installation, engine execution or
activation was performed for this proposal. Container/WSL metadata checks do not
qualify appliance networking. EKS/Helm is outside the appliance runtime; no change.

Licensing evidence identifies MPL-2.0 plus additional notices in Debian's
[copyright record](https://metadata.ftp-master.debian.org/changelogs/main/i/isc-kea/isc-kea_2.6.3-1%2Bdeb13u1_copyright).
Full transitive license/source redistribution review and SBOM remain pending;
upstream availability is not legal sign-off. No premium hooks are proposed.

## Independent review gates

- Exercise unmask, enable, package triggers, interrupted configuration and reboot against the persistent mask; assert no stock daemon starts.
- Compare the host's loaded AppArmor policy before/after, including failure paths. A private mount namespace does not make AppArmor effects local.
- Test a compromised worker attempting AF_PACKET capture/transmission outside its authorized link and DHCP traffic; require an enforced denial.
- Map every shipped binary to its exact source archive, license and redistribution obligations. The main engine license does not cover all transitive artifacts.

These are required future tests, not completed installation evidence.
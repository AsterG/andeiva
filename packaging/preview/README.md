# ANDEIVA Firewall Alpha Preview

This experimental Debian 13 AMD64 package runs the existing administrative
workflow continuously under systemd. Policy enforcement remains confined to three
owned test network namespaces. It does not enable a host firewall, forwarding,
NAT, inspection engines or production authentication.

## Runtime contract

The package reuses the canonical configuration schema, transaction coordinator,
nftables compiler/readback, confirmation guardian, RBAC, HTTPS API, CLI and frontend.
The previous disposable laboratory command remains a separate test tool.

| Unit | Responsibility and authority |
|---|---|
| `andeiva-preview-namespaces.service` | Root setup/lifecycle of three isolated namespaces, fixed fixture tools, namespace pin and root-only probe control |
| `andeiva-preview-helper.service` | Separate service identity, only `CAP_NET_ADMIN`, pinned gateway namespace, bounded typed policy operations |
| `andeiva-preview-api.service` | Separate unprivileged identity, configuration/audit storage, authentication, API and static frontend |
| `andeiva-preview-api.socket` | Exact authorized IPv4 LAN address and interface; no wildcard or WAN listener |
| `andeiva-preview.target` | Explicit enable/start/stop boundary for the complete preview |

The new local transport is private and versioned. Both peers validate the Unix
socket credentials and filesystem ownership; only one controller is admitted.
The helper assigns a new connection epoch, binds requests to the run and namespace,
and requires recovery before policy mutations. Existing public REST and
transaction semantics do not change. No request accepts an executable, raw
nftables script, namespace name or arbitrary filesystem path.

The API inherits the systemd listener and verifies its address and device binding.
Only peers in the configured LAN prefix are admitted, using their actual socket
address. Forwarding headers cannot grant access. TLS uses the provisioned LAN SAN
and an explicit local CA; installation does not change trust on client machines.

Automatic API recovery retains the helper and its independent confirmation deadline.
Recovery attempts are rate-limited; an explicit service stop may propagate to the
target and is not equivalent to automatic recovery.
If the API exhausts its restart budget, administration can remain unavailable
while the helper preserves the last verified policy and its confirmation guardian.
An active target alone is not a health check. Recovery requires an explicit full
stop, cleanup verification and restart; it does not automatically confirm changes.
Stopping or losing the helper stops the complete preview, including its socket
and namespaces. A reviewed restart then reconciles durable state; uncertainty
never becomes a confirmed revision. A restart in the same OS boot recovers
Running. A new OS boot selects Startup, using a durable boot marker written only
after successful configuration recovery. Invalid metadata blocks startup.

The namespace service needs root and namespace/mount capabilities to create and
pin its isolated network. Its mount must be visible to systemd, so it does not use
a private filesystem namespace. It accepts no remote requests; its local probe
socket is root-only. This trusted setup component is an explicit preview limitation.
API and helper units use stricter filesystem and capability restrictions.

Before creating namespaces, the preview requires ten continuous seconds of
unchanged host snapshots, with a thirty-second deadline. This accommodates the
observed DHCP startup race even when `network-online.target` is already active.
It is a bounded stability check, not proof that every network manager has finished.
The accepted snapshot remains the baseline: later host changes still stop the
preview. There is no automatic rebasing, route modification or forced unmount.

## Persistence and package lifecycle

Service accounts are allocated by Debian; existing unrelated identities are not
reused silently. Provisioning is an explicit local administrator action. Upgrades
preserve accounts, CA/server keys, operator credentials, journal and audit files.
No package script enables or starts the preview before provisioning and review.

Authentication and transaction audit are protected, bounded storage. Exhaustion
fails closed; protected records are never silently truncated to restore access.
Traffic observations remain the existing bounded in-memory history and start a
new stream after API restart. These are not connection logs.

Remove stops the full preview and retains configuration and protected state.
Purging package metadata does not erase operator data automatically. A downgrade
requires an explicit compatibility check and backup; this package does not provide
signed appliance updates, A/B rollback or power-loss guarantees.

## Validation status

See the [native validation report](VALIDATION.md) for observed package versions,
scenarios and limitations. Installing a package or passing unprivileged CI alone
does not establish native runtime or LAN isolation. No production readiness or
release is claimed.

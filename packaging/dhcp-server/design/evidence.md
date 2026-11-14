# TP-DHCP-LAN-001 dependency evidence

Captured 2026-11-13, completed 20:20 UTC. Documentation evidence only: no package
installation, package script execution, VM access, server startup or release
authorization. [EN](en.md) · [ES](es.md) · [PT](pt.md).

## Verified inputs and limits

WSL Ubuntu24.04 build environment, APT2.8.4; isolated APT configuration, empty
dpkg status, dedicated lists/cache/logs, Debian trixie/main, trixie-updates/main,
trixie-security/main HTTPS sources. No host package database used as the resolver
baseline. Architecture-specific resolution, Recommends/Suggests disabled, TLS,
signature and metadata expiry verification enabled. Reused the previously staged
Debian archive keyring; its digest identifies the evidence input, not a new
customer trust-anchor provisioning policy.

| Target | Closure packages, including architecture all | Archive bytes | Declared Installed-Size KiB |
|---|---:|---:|---:|
| amd64 | 51 | 17,801,620 | 65,537 |
| arm64 | 51 | 16,737,816 | 80,424 |

There are 94 distinct archives: 43 per architecture plus eight shared `all`
archives. [Full package/version/architecture/size/SHA-256 inventory](closure-2026-11-13.tsv).
All 94 archive hashes were separately compared with SHA256 fields from the
authenticated APT package indexes. Both download-only runs completed. Both
subsequent **download-only + no-download** runs completed from cache. Resolver
plans reported zero upgrades/removals and 51 additions relative to empty status;
this is not an executed transaction. Declared installed size is metadata, not
measured disk/RAM. Native Debian13 APT installation and arm64 execution remain
unqualified.

This is the full explicit Depends/Pre-Depends closure selected by this solver,
not an Essential base system. Debian packages may rely on Essential packages
without declaring every dependency. A release builder must also authenticate and
validate the actual minimal Debian target baseline and exact transaction delta.
This capture cannot authorize replacing installed libraries with its versions.
No database server, Kea metapackage, DHCPv6, DDNS or control-agent is in the closure.

The complete signed indexes and downloads are retained in the owning worktree's
ignored `.tmp/kea-review`; they are not redistributed in this documentation commit.
Missing raw evidence prevents reproducing this historical capture solely from
these documents; use a pinned signed snapshot for a new release capture. Source
archives, complete license audit and SBOM are pending, explicitly not verified here.

## Provenance hashes

| Input | SHA-256 |
|---|---|
| trixie InRelease | `0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675` |
| trixie-updates InRelease | `f9e3adc67d9988ec79270cd4c572d312702530c41d30d29cc0b2b0c735dd02d2` |
| trixie-security InRelease | `45c9486e269272524f1003908915267c314f7c0c065781eaf8841e2eb561967a` |
| Debian archive keyring | `506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017` |

Independent `gpgv` verification succeeded on each InRelease. Valid signer primary
fingerprints included the Debian13 archive key
`04B54C3CDCA79751B16BC6B5225629DF75B188BD`, security key
`5E04A1E3223A19A20706E20F9904613D4CCE68C6`, and stable release key
`41587F7DB8C774BCCF131416762F67A0B2C39DE4` as appropriate; metadata also contained
valid Debian12 signatures. Debian's [published key information](https://ftp-master.debian.org/keys.html)
is a cross-check, not independent authorization to trust a downloaded key.

Stable metadata date: 2026-09-12 07:55:41 UTC. Updates: 2026-11-13 14:10:04 UTC,
valid until 2026-11-20 14:10:04 UTC. Security: 2026-11-13 16:33:04 UTC, valid until
2026-11-20 16:33:04 UTC. Do not reuse this evidence as perpetually valid update
metadata or disable expiry checks.

## Package inspection

Both Kea components resolved to `2.6.3-1+deb13u1`. Extracted control metadata:

| Package | Direct relation |
|---|---|
| kea-dhcp4-server | Pre-Depends init-system-helpers >=1.54~; Depends kea-common exact version, libc6 >=2.34, libgcc-s1 >=3.0, libstdc++6 >=14 |
| kea-common | Depends adduser, libc6 >=2.38, libgcc-s1 >=3.0, liblog4cplus-2.0.5t64 >=2.0.8, libmariadb3 >=3.0.0, libpq5 >=9.1~, libssl3t64 >=3.4.0, libstdc++6 >=14 |

Cross-checked with the Debian [server](https://packages.debian.org/trixie/amd64/kea-dhcp4-server)
and [common](https://packages.debian.org/trixie/amd64/kea-common) records. The
extracted amd64 package contents, not a guessed default, establish these effects:

- Server postinst attempts SysV defaults/start or restart, systemd helper
  unmask/enable and daemon-reload/start or restart. It also updates/reloads its
  AppArmor profile. SHA-256:
  `b15bda4df9e88b84ed72fc2b9358515a8444b785542cce23e9bcd9cc8b3198e6`.
- Common postinst creates `_kea`, sets `/etc/kea` ownership and handles historical
  overrides; it reloads the LFC AppArmor profile. SHA-256:
  `e19b2e36e9b891969f0d70bc1ae05d6d6f988e0516898c171f22655b92f8dbe6`.
- Stock service runs as `_kea`, requests NET_BIND_SERVICE and NET_RAW, and has a
  multi-user install target. SHA-256:
  `a84cba0ffa110faac8ecb81d3552e7086ecbf8dd790fb10dd9d7dca6f6e3b69c`.
- AppArmor allows raw packet sockets and the LFC executable; its default paths
  are not yet an ANDEIVA isolation profile. No claim that upstream policy is
  sufficient for this integration.

Debian's [invoke-rc.d](https://manpages.debian.org/trixie/init-system-helpers/invoke-rc.d.8.en.html)
and [deb-systemd-invoke](https://manpages.debian.org/trixie/init-system-helpers/deb-systemd-invoke.1p.en.html)
consult local policy. This does not prevent enablement or arbitrary script
effects. Exact script/mask tests are required per release. Full closure maintainer
script review is pending; no generic safe-install claim is made.

## Reproduction boundary

The capture used an absolute private `APT_CONFIG` redirecting **all** apt config,
source parts, state/status, lists, archives and logs into scratch; no host APT
configuration hooks or installed package state were inherited. With the same
signed indexes and keyring, the read/download checks were:

```sh
# Builder-only: APT_CONFIG must already point to the isolated configuration.
apt-get -s --no-install-recommends --no-remove install kea-dhcp4-server:amd64
apt-get --download-only --yes --no-install-recommends --no-remove install kea-dhcp4-server:amd64
apt-get --download-only --no-download --yes --no-install-recommends --no-remove install kea-dhcp4-server:amd64
# Repeat with APT::Architecture=arm64 and target kea-dhcp4-server:arm64.
# Compare each downloaded SHA256 with apt-cache show package:arch=exact-version.
# gpgv --keyring PRIVATE_REVIEWED_KEYRING each_InRelease
```

Never run these against a customer's default APT configuration. No install
command, installer implementation or new trusted-key acceptance mechanism is
provided by this proposal.

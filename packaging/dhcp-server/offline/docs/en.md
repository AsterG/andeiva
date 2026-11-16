# Experimental offline installation, inactive DHCP server

This development installer adds ten exact Debian packages to an already installed
41-package baseline on Debian 13 amd64. It does not enable a DHCP service, select
a production engine, configure interfaces, change the management API or qualify
lease persistence. Native installation, interruption and reboot tests are pending.

## Build and review

On an unprivileged Linux development host, provide the exact public files in
`check/profile/archives.tsv`, `supply-chain.json`, `source-map.json` and
`provenance.json`. `DEB_CACHE` contains the 51 baseline/delta archives used for
notice extraction; only the ten new archives enter the output. `SOURCE_CACHE`
contains `downloads/<source>/<filename>`, `state/lists/<filename>` and the
previously authenticated Debian archive keyring at
`keys/debian-archive-keyring.gpg`. `BINARY_LISTS` contains the signed InRelease
files and uncompressed amd64 Packages indexes named in `provenance.json`.
These are portable build inputs, not references to an operator's private baseline.
Source URLs and hashes are listed in `source-map.json`; binary archive locations
are in the authenticated Packages indexes. Do not substitute versions.

The separate `base-files_13.8+deb13u7_amd64.deb` reference supplies Debian's actual
common-license texts, SHA256
`fcd42bb5cb63f7bfc4326a92541247872206d60a192fdff65ca14eb83ed408b9`.
It is **not installed** or added to the ten-package delta. Obtain it from
`https://deb.debian.org/debian/pool/main/b/base-files/` on the development host.
No online acquisition runs on the appliance. The bundler requires Python 3,
gpgv, dpkg-deb, Go 1.27.4 and the repository's already cached Go modules. It does
not install tools or execute maintainer scripts; source archives are copied intact.

```sh
python3 packaging/dhcp-server/offline/build.py \
  "$DEB_CACHE" "$SOURCE_CACHE" "$BINARY_LISTS" "$BASE_FILES_REFERENCE" "$NEW_OUTPUT"
go test -race ./packaging/dhcp-server/offline/check
go vet ./packaging/dhcp-server/offline/check
```

Build authentication verifies InRelease signatures with the pinned previously
authenticated keyring, index hashes, exact package/source versions and archive
hashes. At installation, the existing Debian `/usr/bin/sqv` and fixed installed
`/usr/share/keyrings/debian-archive-keyring.pgp` recheck signed metadata. Missing
verifiers, unexpected files, expired security/updates metadata, changed baseline,
newer versions, foreign architecture or unreviewed helper hashes cause refusal.
Main trixie omits Valid-Until; no bounded freshness claim is made for that suite.
Refreshing this profile requires review, not disabling freshness checks.

The output ID is SHA256 of its sorted `SHA256SUMS`, not a publisher signature.
An authorized operator must independently trust the exact reviewed code and bundle
ID before root execution. No signed public release is provided. Stage the verified
bundle as root-owned, single-link regular files with no writable aliases or ACLs
at `/var/lib/andeiva-dhcp-bundles/ID`; binary executable, other files read-only to
nonroot users. Validate the full inventory before executing its checker.

## Capture first; installation requires a second review

```sh
# Authorized native laboratory root only; no installation effects:
/var/lib/andeiva-dhcp-bundles/ID/bin/check capture > capture.json
sha256sum capture.json
```

Capture exports paths, ownership, inode identities and hashes, not account or
configuration contents. It covers installed package scripts/triggers, alternatives,
AppArmor, systemd/SysV aliases, accounts and dpkg state. Review the actual handlers
and effects locally before approving that exact SHA256. A newly observed hash is
not automatically approved. An existing policy hook, Kea installation/account,
MySQL configuration or running DHCP server is outside this fresh-only profile.

After independent review and an external recovery backup, the explicit effectful
development command is:

```sh
systemd-run --unit=andeiva-dhcp-offline-install.service --service-type=exec \
  --property=KillMode=control-group --property=SendSIGKILL=yes \
  --property=Delegate=no --property=RemainAfterExit=yes \
  --property=RuntimeMaxSec=720 --property=TimeoutStopSec=15 \
  /var/lib/andeiva-dhcp-bundles/ID/bin/check install ID APPROVED_CAPTURE_SHA256
```

The fixed unit must be absent before this authorized laboratory invocation. The
installer checks its real MainPID, invocation, cgroup and kill policy; direct
shell installation is refused. It also requires 512 MiB and 4096 free inodes on
the relevant filesystems as a minimum reserve, not a measured upper bound.
The outer operator must inspect the current invocation result and prove the unit
contains zero processes after completion/failure before any cleanup or recovery.
The checker verifies only itself remains before its success receipt. It does not
claim a timeout kills every descendant itself. Capture now includes dpkg's own
configuration and local-only account lookup policy; recapture after code changes.

APT uses its own POSIX package locks, empty private sources/configuration, local
archives, `--no-download --no-remove --no-upgrade --no-install-recommends`.
The VERSION 3 pre-install hook validates the entire effective action list and
rechecks the capture while the real APT frontend lock is held. Exactly ten fresh
unpacks and configurations are allowed; no extra package, replacement, removal,
downgrade or missing configure action is admitted. No simulation is effect authority.

Before unpack, an exclusive fsynced recovery record, protected originals, persistent
administrative `kea-dhcp4-server.service` mask and owned scoped `policy-rc.d`
deny-101 guard are created. This **fresh-only persistent guard** supersedes the
earlier private-overlay proposal for this experiment: an existing policy is always
refused, never replaced. The guard and mask remain after success and every failure.
Reviewed package scripts still create accounts/configuration, update alternatives,
reload AppArmor and run installed triggers. These are real privileged effects.

Success requires exact package postconditions, unchanged versions/status of every
previous package, clean dpkg audit, disabled start links, masked/inactive stock
unit and no observed Kea process or UDP67 listener. It does not by itself prove no
transient AF_PACKET activity; native packet/process observation remains mandatory.
The main package log is capped at 4 MiB and overflow fails the operation; APT's
duplicate terminal log is disabled, not its history or dpkg audit. Other third-party
log growth, total disk/inode demand and native CPU/RAM remain unqualified.

## Failure and recovery

Retain `/var/backups/andeiva-dhcp-offline`, mask and policy. A repeated install
refuses retained operations; no automatic resume, marker clearing, downgrade,
purge, account deletion or shared-library removal is implemented. Timeout is not
proof that all dpkg descendants stopped. Prove package-manager/process drainage,
inspect dpkg state, retained records and exact backup before a separately reviewed
recovery. The record contains protected originals and hashes, not a complete
filesystem rollback. Do not copy an old dpkg status file over a live installation.
Upgrades and active/persistent-lease rollback require separate qualification.

## Notices and sources

`supply-chain.json` inventories ten new packages and 41 required installed ones;
it is not a complete appliance SBOM. Original package notices and Debian common
license texts are retained. `license_declared` transcribes notices; NOASSERTION
is used for legal conclusions; plaintext notices have descriptive classifications. No blanket
Apache license applies to third-party packages; Apache-2.0 covers ANDEIVA code only.
The bundle includes all seven corresponding source versions and archive hashes,
including Debian packaging changes. Keep these files available alongside any
authorized binary delivery and preserve notices. This is source availability,
not a legal-clearance decision or a claim that every redistribution obligation
has been fulfilled. Sources are not unpacked, compiled or installed on the appliance.

# Experimental Debian package

[Español](es.md) · [Português](pt.md)

This procedure covers `andeiva-experimental` version `0.0.0~exp1` on a Debian 13
amd64 development VM. It packages the informational CLI and liveness server. It
does not install a firewall, authentication, VPN, traffic inspection, a privileged
management agent, signed `.sgu` updates or A/B recovery. The frontend remains a
separate development page; this service does not serve web administration.

The commands describe the package contract. A successful laboratory run must be
recorded against the exact build; this guide is not a claim that those tests passed.

## Requirements and roles

Build as an ordinary user on a trusted Linux workstation with the source revision,
Bash, Git, Go 1.27.3, `dpkg-deb`, `sha256sum` and standard build utilities already
available. No Docker runtime is needed. Missing prerequisites are a blocker; do not
make the development VM download dependencies automatically.

Provision the reviewed Go module cache on the build workstation before going
offline, including module-graph metadata. Set `GOMODCACHE` to that existing cache;
if omitted, the builder uses the path reported by `go env GOMODCACHE`. It verifies
the cache with `go mod verify` and builds with `GOPROXY=off`, `GOSUMDB=off` and
read-only module manifests. It never downloads modules. Missing or altered cached
dependencies fail the build, even if module-graph metadata describes packages
that are not linked into the scaffold. Do not replace the cache with an empty one.
The package includes the sanitized module graph, `go.mod`, `go.sum`, complete Go
module license/patent texts and their SHA-256 inventory under
`/usr/share/doc/andeiva-experimental/dependencies/`.

The VM must already have systemd as its running system manager, the package
dependencies `systemd (>= 257)` and `init-system-helpers (>= 1.69~)`, Bash, `dpkg`,
`sha256sum`, `ps` and `ss`. The health probe needs neither curl nor Python.

Installation, service control and removal require an explicitly authorized root
console in the isolated Debian 13 VM. Confirm its identity, snapshot and working
recovery console before changes. These steps do not apply to the Windows host or
an operational gateway. Keep credentials out of commands, files and shared logs.

The intended appliance minimum is 2 GB RAM and 64 GB disk capacity. This package
does not certify that capacity profile or an appliance installer. Record actual
RAM, free space and storage separately; capacity is not free space.

## Build and transfer

From the trusted source root, as a non-root user:

```bash
set -euo pipefail
umask 077
test "$(id -u)" -ne 0
export GOENV=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOTELEMETRY=off
export GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"
test -d "$GOMODCACHE"
test "$(go env GOVERSION)" = go1.27.3
out_dir=$(mktemp -d "${TMPDIR:-/tmp}/andeiva-debian-package.XXXXXX")
bash packaging/debian/build.sh '0.0.0~exp1' "$out_dir"
cd -- "$out_dir"
sha256sum --check --strict SHA256SUMS
sha256sum SHA256SUMS
```

Under WSL, `OUT_DIR` must be on the Linux filesystem, not `/mnt/c` or another
Windows-mounted directory. Package control files require real Unix permissions;
DrvFS can report directory mode `777`, causing `dpkg-deb` to reject the build.
Keep `TMPDIR` on a Linux filesystem or leave it unset. If the build aborts, do not
treat the output directory as a completed artifact or relax permission checks.

The outputs are `andeiva-experimental_0.0.0~exp1_amd64.deb`, `SHA256SUMS` and
`build-info.txt`. The builder accepts an optional third argument
`SOURCE_DATE_EPOCH`, or the environment variable of that name; otherwise it uses
the source commit timestamp. Retain the source revision and build information.
Building a later experimental version uses the same interface with an explicitly
chosen version, such as `0.0.0~exp2`, and a new output directory.

Transfer the complete output through authorized SSH file transfer, a local medium,
or an already approved shared folder. Verify the SSH host identity through a trusted
channel; never disable host-key verification. Do not enable new sharing services,
root SSH, port forwards or host/VPN network changes for this procedure.

Record the SHA-256 of `SHA256SUMS` through an independent trusted channel. On the VM,
in the transferred directory, compare that value before checking the package:

```bash
sha256sum SHA256SUMS
sha256sum --check --strict SHA256SUMS
```

A checksum detects changed bytes; it does not authenticate the publisher when the
checksum and package come from the same untrusted source. These are locally built
experimental artifacts, not signed releases. Stop if trust or integrity cannot be
established. Keep the verified package available for removal/reinstallation tests.

## Install in the VM

Open the authorized root console in the VM and enter the verified bundle directory.
Review the OS and package metadata: Debian 13, `amd64`, package
`andeiva-experimental`, version `0.0.0~exp1`.

```bash
set -euo pipefail
umask 077
test "$(id -u)" -eq 0
cat /etc/os-release
test "$(dpkg --print-architecture)" = amd64
package_file="$PWD/andeiva-experimental_0.0.0~exp1_amd64.deb"
test -f "$package_file"
dpkg-deb --field "$package_file" Package Version Architecture
dpkg --install "$package_file"
dpkg-query --show --showformat='${Package} ${Version} ${Status}\n' andeiva-experimental
```

The package installs `/usr/bin/andeiva`, `/usr/lib/andeiva/andeiva-api`,
`andeiva-api.service` and the conffile `/etc/andeiva/andeiva-api.env`. The service
uses a dynamic unprivileged identity and `/run/andeiva-api` for runtime files;
that directory is not persistent application data. A bounded readiness helper is
installed at `/usr/lib/andeiva/wait-ready`; license and build information are under
`/usr/share/doc/andeiva-experimental`.

Initial configuration requests service enablement and startup. Debian service
policy, an operator-disabled unit or a mask can defer startup. Successful `dpkg`
configuration alone is not evidence that the service is running. Inspect the
policy/state and stop if activation is not authorized; do not bypass it.

## Configuration, health and service control

The default conffile contains `ANDEIVA_LISTEN_ADDR=127.0.0.1:4000`. Keep the
unauthenticated service on loopback. Do not use a LAN address, wildcard listener or
reverse proxy to expose it. If an authorized test changes the port, choose an
unoccupied numeric loopback address and adjust every probe below. Do not source
the conffile as a shell script. Restart the service after an approved edit.

```bash
cat /etc/andeiva/andeiva-api.env
systemctl is-enabled andeiva-api.service
systemctl is-active andeiva-api.service
andeiva help
andeiva --lang en status
andeiva --lang es status
andeiva --lang pt status
probe_addr=127.0.0.1:4000
ANDEIVA_LISTEN_ADDR="$probe_addr" /usr/lib/andeiva/andeiva-api --healthcheck
```

The probe exits with code 0 and no output when the exact liveness response is
received; it uses no configured proxy. The endpoint returns `{"status":"ok"}` for
process liveness only. CLI status explicitly
states that gateway features are not implemented. An unknown command such as
`andeiva config` exits with code 2; it cannot configure a gateway.

Use these operations only on the identified VM:

```bash
systemctl stop andeiva-api.service
systemctl start andeiva-api.service
systemctl restart andeiva-api.service
systemctl status --no-pager andeiva-api.service
journalctl --unit andeiva-api.service --boot --no-pager
```

`stop` affects the current run, not boot enablement. To keep the service stopped
across boots, use `systemctl disable --now andeiva-api.service`. To restore startup
when authorized, use `systemctl enable --now andeiva-api.service`. A deliberate mask
must be reviewed by its owner; package installation must not silently remove it.

## Upgrade and explicit rollback

Before upgrading, retain the previous verified `.deb`, its manifest and a copy of
the conffile in an operator-approved persistent backup directory. Do not store a
recovery copy under `/run`. Assign `next_deb` the absolute path of the new package
after verifying its own trusted checksum manifest. Check package name, architecture
and intended version before installing:

```bash
test -f "$next_deb"
dpkg-deb --field "$next_deb" Package Version Architecture
dpkg --install "$next_deb"
dpkg-query --show --showformat='${Version}\n' andeiva-experimental
```

The environment file is a Debian conffile. Review any conffile prompt rather than
forcing a replacement; preserve the intended local loopback setting. Upgrades
respect operator disablement/masking and local service policy. If the unit was
running, verify its restart, liveness and configuration afterwards. If it was
disabled or masked, verify that the package did not unexpectedly activate it.

Rollback is an explicit package downgrade, not atomic OS recovery. Assign
`rollback_deb` the absolute path of the previous trusted package and verify its
manifest again. Confirm that its configuration format is compatible; then:

```bash
test -f "$rollback_deb"
dpkg-deb --field "$rollback_deb" Package Version Architecture
dpkg --install "$rollback_deb"
dpkg-query --show --showformat='${Version}\n' andeiva-experimental
```

Repeat the health and service-state checks. Stop on a failed maintainer script or
incompatible configuration; retain diagnostics and use the approved VM recovery
plan. No database migration, rollback partition or signed offline update chain is
provided by this package.

## Remove, reinstall and purge

Removal stops the service and removes packaged executables while retaining the
conffile. Verify retention; do not delete unrelated configuration or user data:

```bash
dpkg --remove andeiva-experimental
test -f /etc/andeiva/andeiva-api.env
test ! -e /usr/bin/andeiva
test ! -e /usr/lib/andeiva/andeiva-api
```

To reinstall, verify the selected package and manifest again, run
`dpkg --install "$package_file"`, and repeat service, conffile and health checks.
The retained configuration must be reviewed, not assumed to be the package default.

Purge is a separate explicit choice that removes the package conffile:

```bash
dpkg --purge andeiva-experimental
test ! -e /etc/andeiva/andeiva-api.env
```

Purge is not a factory reset. It does not erase operator backups, unrelated user
files or system journal history. No recursive cleanup command is required.

## Reboot verification and resource observations

After an authorized installation, record unit enablement, effective listener,
configuration hash and a process sample:

```bash
systemctl is-enabled andeiva-api.service
systemctl is-active andeiva-api.service
sha256sum /etc/andeiva/andeiva-api.env
systemctl show andeiva-api.service --property=MainPID,DynamicUser,RuntimeDirectory,MemoryCurrent,CPUUsageNSec
api_pid=$(systemctl show andeiva-api.service --property=MainPID --value)
test "$api_pid" -gt 0
ps -p "$api_pid" -o pid=,uid=,rss=,pcpu=,etime=
ss -ltnp
```

Where accounting is unavailable, record it as unavailable. These samples are not
throughput, capacity or idle-soak benchmarks. Preserve results privately and redact
unrelated processes or addresses before sharing them.

Only with explicit approval to restart this VM and a verified recovery snapshot,
run `systemctl reboot` from its console. Reconnect through the approved console,
repeat the state/hash/health checks and confirm the listener remains on loopback.
The runtime directory may be recreated and the dynamic UID may change. Neither is
persistent identity. Record an actual post-boot result; a configured enablement
symlink does not prove successful startup.

If dependencies, a transfer path, console recovery or authorization are missing,
leave the procedure pending. On bind, startup or health failure, inspect this
service's journal without widening exposure or disabling protections. Record the
exact revision, package hashes, operations, exit codes and limitations. This test
does not validate appliance security capabilities or complete the project phase.

`ANDEIVA_SERVICE_IDENTITY_CONFLICT` or `ANDEIVA_INSTALL_PATH_CONFLICT` means an
existing account, group or path conflicts with installation. Preserve it and review
ownership; do not delete unrelated files or accounts to make installation succeed.
`ANDEIVA_SERVICE_DEFERRED` requires reviewing service policy and actual unit state.

## Repeatable package tests

Run archive checks on the trusted Linux build host, from the source root. They
require Python 3 on that host, not on the VM. Set `exp1_deb` and `exp2_deb` to the
absolute paths of the verified `0.0.0~exp1` and `0.0.0~exp2` packages. The report
directories must be new and outside the source tree:

```bash
checks_dir=$(mktemp -d "${TMPDIR:-/tmp}/andeiva-package-checks.XXXXXX")
bash packaging/debian/tests/static-package.sh --package "$exp1_deb" --evidence-dir "$checks_dir/exp1"
bash packaging/debian/tests/static-package.sh --package "$exp2_deb" --evidence-dir "$checks_dir/exp2"
sha256sum -- "$exp1_deb" "$exp2_deb"
```

The VM lifecycle suite is an alternative to the manual installation above: it
requires an isolated Debian 13 amd64 VMware VM with no previous package record,
unit, package paths or service-start policy, and free ports 4000 and 44001. It
refuses existing state; never delete unrelated data or policy to satisfy its
preflight. Root authorization and a confirmed recovery snapshot are mandatory.

On the VM, set `exp1_deb` and `exp2_deb` to the transferred package paths,
`exp1_sha256` and `exp2_sha256` to the hashes recorded by the trusted host, and
`snapshot_ref` to the actual confirmed snapshot reference. Use an existing
root-owned parent directory for new reports. From the trusted test source root:

```bash
run_evidence="/var/tmp/andeiva-native-run-$(date -u +%Y%m%dT%H%M%SZ)"
bash packaging/debian/tests/vm-lifecycle.sh run \
  --install-deb "$exp1_deb" --install-sha256 "$exp1_sha256" \
  --upgrade-deb "$exp2_deb" --upgrade-sha256 "$exp2_sha256" \
  --evidence-dir "$run_evidence" --snapshot-ref "$snapshot_ref" \
  --lab-ack ANDEIVA-ISOLATED-LAB
```

The suite installs, changes its own conffile, upgrades, explicitly downgrades,
checks disabled/masked state, deliberately kills the service process, tests invalid
configuration and recovery, then removes, purges and reinstalls its test package.
A successful run ends with that package purged. Failure stops the test-owned
service and retains state for diagnosis. The suite does not reboot the VM, modify
networks, install dependencies or operate snapshots. No test result is implied here.

The actual reboot gate is separate, also starting from a clean authorized VM:

```bash
reboot_evidence="/var/tmp/andeiva-native-reboot-$(date -u +%Y%m%dT%H%M%SZ)"
bash packaging/debian/tests/vm-lifecycle.sh prepare-reboot \
  --install-deb "$exp1_deb" --install-sha256 "$exp1_sha256" \
  --evidence-dir "$reboot_evidence" --snapshot-ref "$snapshot_ref" \
  --lab-ack ANDEIVA-ISOLATED-LAB
```

Record the report path and snapshot reference. Preparation leaves the package
installed; it is not a post-boot pass. Perform the separately authorized VM reboot
from its console. After reconnecting, restore `reboot_evidence` and `snapshot_ref`
to their recorded values and return to the test source root:

```bash
bash packaging/debian/tests/vm-lifecycle.sh verify-after-reboot \
  --evidence-dir "$reboot_evidence" --snapshot-ref "$snapshot_ref" \
  --lab-ack ANDEIVA-ISOLATED-LAB
bash packaging/debian/tests/vm-lifecycle.sh cleanup-reboot \
  --evidence-dir "$reboot_evidence" --snapshot-ref "$snapshot_ref" \
  --lab-ack ANDEIVA-ISOLATED-LAB
```

Verification requires an actual changed boot ID and unchanged test-owned files;
cleanup removes the test package. Keep reports private and retain failures. If a
guard rejects ownership or state, review it without bypassing the guard.

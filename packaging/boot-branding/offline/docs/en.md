# Experimental offline boot bundle

For authorized internal development only. This is not a signed appliance update, a release, an A/B installer or authorization to redistribute the dependency bundle. A checksum detects changes; obtain the bundle and its expected checksum through an independently trusted channel. Never execute an untrusted installer as root.

## Build

Use a nonroot Debian 13 AMD64 development environment with APT, its Debian archive keyring, sqv, dpkg, Go matching `go.mod`, GNU tar/coreutils, gzip and util-linux. Only this development step accesses the fixed official Debian repositories. APT signature, date, expiry and HTTPS validation remain enabled.

```sh
bash packaging/boot-branding/offline/build.sh \
  /private/target-dpkg-status /private/reviewed-product-debs \
  /private/bundle-output 1794355200
```

The product directory must contain exactly two reviewed packages with the same experimental version: `andeiva-boot-branding` and `andeiva-boot-activation`. The activation package must declare offline installation guard version 1. The privately supplied status influences resolution but is not included in the bundle. Preserve it privately to repeat the build. Signed repository metadata and dependency versions may change; byte reproducibility requires identical resolved inputs and metadata, not just the same command.

Before resolution or installation, the target must already contain configured `grub-common`, `grub2-common`, `grub-pc` and `grub-pc-bin` version `2.12-9+deb13u2` (amd64), plus `initramfs-tools` and `initramfs-tools-core` version `0.148.4` (all). This bundle cannot install or upgrade them. Only subsets of 26 reviewed, compiled dependency tuples are admitted; a newly signed package/version/hash still requires profile review. Keep security updates current through a separately qualified procedure; do not bypass this guard or interpret it as indefinite version retention.

## Inspect and install

The current installer accepts Debian 13 AMD64, BIOS and a single ext4 root filesystem containing `/boot`, `/etc`, `/usr` and `/var/backups`, with no foreign dpkg architectures. Other layouts are refused. These capability checks do not qualify every device or hypervisor. Ensure sufficient free space, a healthy dpkg database, two complete kernels and a tested independent recovery path before installation. It does not install a kernel or make existing Debian an A/B system.

Verify the expected archive checksum before extraction. Extract only a trusted bundle into a controlled staging directory; inspect it before an authorized operator places its root-owned, non-writable contents under `/var/lib/andeiva-boot-bundles/INVENTORY_SHA256`. The build prints that inventory identifier (SHA-256 of SHA256SUMS). Do not include private status, credentials or diagnostic evidence in this directory.

```sh
cd /var/lib/andeiva-boot-bundles/INVENTORY_SHA256
./install.sh inspect
./install.sh install --recovery-verified
```

`inspect` validates signatures, package hashes, exact inventory and a simulated offline APT plan; it removes its temporary staging directory. `install` repeats validation, requires the operator recovery acknowledgement and takes boot/configuration backups before running APT in a private mount namespace. Only that namespace sees `update_initramfs=no`, bound read-only. Host APT sources, preferences and invocation hooks are not loaded. No online APT, upgrades, removals, theme activation or reboot are performed. Existing packages must already match the required versions; existing activation tools must report `offline_install_guard: 1`. Older tools require a separately reviewed upgrade.

Successful installation verifies package versions, guard capability, boot hashes, kernel inventory and the unchanged host initramfs policy before clearing the durable pending marker. Repeating the same completed installation reports `ANDEIVA_OFFLINE_ALREADY_INSTALLED`. Branding activation remains a separate recovery-gated operator action.

The inventory identifier binds every payload file, including the installer and checker; it is SHA-256 of the canonical `SHA256SUMS` file. Old development IDs based only on the package manifest are not accepted. Simulation and installation logs combine stdout/stderr, remain at most 4 MiB and show an explicit footer on truncation. Logging drains remaining output even after a write failure. A timeout covers both producer and logger, including descendants holding the pipe. Truncation, write failure or either pipeline error retains pending state even if APT installed every package successfully.

Only APT's duplicate terminal log is redirected to `/dev/null`; the bounded primary merged log, APT history and dpkg action audit remain. Other OS, history/planner and maintainer-script logs are not magically covered by the 4 MiB cap and still require storage policy and native qualification. Runtime uses rehashed canonical APT cache names, including lowercase `%3a` for version epochs, without enabling downloads.

## Failure and recovery

Any interruption after the pending marker is created leaves `/var/backups/andeiva-boot-offline/install-pending` and private backups in place. A new installation or boot activation must refuse this uncertain state, even when every package appears installed. An APT child can survive its parent; absence of the installer process is not proof that installation stopped.

There is no automatic package rollback, resume or marker-clearing command in this increment. Do not remove the marker or run generic APT repair to bypass it. Authorized recovery must first establish that APT/dpkg and all installation children have stopped, verify backups and the live boot/configuration/package state, then use a separately reviewed recovery procedure or the independently tested snapshot/backup. Keep the evidence private. Uninstalling a product package or deleting the marker does not undo Debian dependency maintainer scripts.

## Validation limits

```sh
go test -race ./packaging/boot-branding/offline/check
go vet ./packaging/boot-branding/offline/check
bash -n packaging/boot-branding/offline/*.sh
```

Pure fixtures and syntax checks do not prove real namespace isolation, interruption recovery, a fresh Debian install or native resource consumption. Those require separate evidence and independent review. The bundle adds no permanent process; installation CPU, memory, time and disk overhead remain to be measured on the target.

The existing Debian trust anchor must be the regular, root-owned, non-writable-by-group/others `/usr/share/keyrings/debian-archive-keyring.pgp`, with trusted ancestors. The conventional `.gpg` symlink alias is not used; arbitrary keyring paths or links are not accepted.

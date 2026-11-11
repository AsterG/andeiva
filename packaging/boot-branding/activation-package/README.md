# Experimental boot activation package

Build both product packages from the same reviewed source, version and epoch as a
normal Linux user. Use the Go version declared in `go.mod`:

```sh
bash packaging/boot-branding/build.sh 0.1.0~alpha1 /tmp/andeiva-theme 1700000000
bash packaging/boot-branding/activation-package/build.sh 0.1.0~alpha1 /tmp/andeiva-activation 1700000000
bash packaging/boot-branding/activation-package/test.sh
```

The activation package contains one Linux AMD64 executable and its documentation.
It has no maintainer scripts, boot configuration, services or automatic reboot.
Installing it does not activate the theme. Its declared dependencies deliberately
match the initially qualified Debian/Plymouth versions; other versions need review.

Dependency installation is a separate gate: Debian's Plymouth maintainer scripts
can rebuild **all** initramfs images. Before installing dependencies, retain a
verified pre-installation backup and test an independent recovery path. Use the
reviewed offline installation procedure; do not bypass dependency checks, disable
filesystem checks or fetch packages online on the appliance. Checksums detect
artifact changes, but are not publisher signatures or a signed appliance update.

After package installation and recovery qualification, run the packaged commands
as the authorized local platform operator:

```sh
andeiva-boot-activation preflight
andeiva-boot-activation prepare --recovery-verified
andeiva-boot-activation apply
andeiva-boot-activation status
```

`pending-reboot` reports prepared boot files, not a successful boot. Reboot,
visual inspection, health, network invariance and recovery must be tested
separately. The tool does not change networking or provide Web/CLI power controls.
Read the [English](../activation/docs/en.md), [Spanish](../activation/docs/es.md)
and [Portuguese](../activation/docs/pt.md) operator guides and the
[compatibility and recovery limits](../activation/DESIGN.md).

Restore with the packaged `andeiva-boot-activation restore` command before
removing theme data. Restoring boot files does not remove the installed Debian
dependencies or undo every operating-system package change. Keep the independent
backup and recovery snapshot; never purge Plymouth automatically as rollback.

The static executable also ships the Go toolchain license as GO_LICENSE. Native compatibility is determined by capabilities and qualification evidence, not a hypervisor or disk label. The explicit diagnostic mode and its private runtime trace limits are documented in the operator guides.

The packaged `apply --redraw-compatibility` mode is explicit and reversible. It adds a standard Plymouth redraw argument without choosing a display mode or driver. Default activation remains unchanged; qualify real boot/recovery and resource cost on each target platform before adopting it. See the operator guides for removal and the prohibition on combining it with diagnostic boot.
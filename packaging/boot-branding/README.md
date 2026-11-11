# ANDEIVA boot branding resources

Status: experimental, inactive theme resources. Native boot, shutdown, recovery and performance qualification are pending. Installing this data package does **not** change the running or next boot configuration.

The GRUB template and Plymouth script use the approved light identity independently of the web theme. The builder copies the complete official logo from `frontend/public/andeiva-logo.png` without modification and verifies SHA-256 `1f79f5ec7f33327c9285c702b63fc5c5a618a28395b2161d594001fdb0199f81`. Decorative backgrounds and activity assets are original generated resources. No fonts or third-party theme code are bundled.

The moving, fixed-width segment indicates activity, not percentage, service health or a successful boot. All theme-owned graphical text is English. External diagnostic messages and prompts remain visible verbatim; they are not rewritten for branding or language.

## Build and inspect without privileges

Use Linux/WSL as a regular user with the repository Go toolchain, `dpkg-deb`, Python 3, `flock` (util-linux) and standard shell utilities. No dependency installation or network access is performed. Use an output directory on a Linux filesystem to preserve Debian ownership/mode metadata. A nonblocking output lock prevents simultaneous publication; complete artifacts are published without replacing existing files.

```sh
bash packaging/boot-branding/tests/run.sh
bash packaging/boot-branding/build.sh 0.1.0~alpha901 /tmp/andeiva-boot-package 1794355200
python3 packaging/boot-branding/tests/check-package.py /tmp/andeiva-boot-package/andeiva-boot-branding_0.1.0~alpha901_all.deb
(cd /tmp/andeiva-boot-package && sha256sum -c SHA256SUMS)
dpkg-deb -I /tmp/andeiva-boot-package/andeiva-boot-branding_0.1.0~alpha901_all.deb
dpkg-deb -c /tmp/andeiva-boot-package/andeiva-boot-branding_0.1.0~alpha901_all.deb
```

The version above is a validation example, not a release. A SHA-256 checksum detects modification; it is not a signature or authorization to install. Customer distribution requires the signed offline update workflow.

There are no maintainer scripts, triggers, dependency installation, services, timers or executables in the package. No `/etc`, `/boot`, EFI, kernel, initramfs, systemd or network paths are included. GRUB and Plymouth do not select this theme merely because its files exist.

## Operator guides

- [English](docs/en.md)
- [Español](docs/es.md)
- [Português](docs/pt.md)
- [Design, threats and qualification gates](DESIGN.md)

Activation, safe deactivation and bootloader changes are intentionally absent from this increment. Do not manually select the theme as a substitute for the pending recovery-gated integration procedure.

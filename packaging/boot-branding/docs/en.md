# Boot branding: operator guide

This experimental package contains inactive graphical resources. It does not install Plymouth, select a theme, regenerate GRUB/initramfs, rename menu entries or change network services. Do not treat a successful package check as a successful boot test.

## Inspect and qualify

Run `bash packaging/boot-branding/tests/run.sh` from the source tree as a regular Linux/WSL user. Build commands and artifact inspection are in the [README](../README.md). The tests install nothing and require no root access. Keep the signed offline provenance and checksums with any artifact; a checksum is not a signature.

Before any future activation: verify authorized VMware/local recovery access, a recoverable snapshot, boot configuration backups, free bytes/inodes and an untouched previous kernel/initramfs. Rehearse recovery first. Installing Plymouth dependencies can trigger initramfs updates and is subject to the same gate. Do not modify Secure Boot, disk layout, interfaces, routes or firewall rules for branding.

## Presentation and diagnostics

The original logo is unchanged. All theme-owned strings are always English, including `Starting system...`, `Restarting...` and `Shutting down...`. The activity bar has no percentage or successful health claim. The web's selected language/theme does not select a boot theme. External errors and password prompts remain unchanged; firmware and early failures cannot be guaranteed invisible.

Esc/text diagnostics, long messages, encrypted prompts and absent graphics require real console qualification. No Web/CLI reboot feature is provided by this package. Do not introduce a shell endpoint to simulate that integration.

## Update, removal and recovery

Activation and its rollback procedure are not implemented in this increment. Do not select these resources manually before the recovery-gated procedure is approved. An inactive package changes only its `/usr/share` resources. After any future activation, restore and verify the prior theme/boot configuration before removing resources referenced by GRUB or initramfs. Do not delete recovery kernels or replace generated files.

See [design and remaining gates](../DESIGN.md). Native rendering, boot/restart/shutdown, kernel update, restoration and active resource measurements remain pending. Existing Debian package rollback is not A/B recovery.

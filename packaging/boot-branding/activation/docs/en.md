# Local boot activation — experimental

For an authorized local platform operator only. This tool is not a Web/API endpoint, installer or signed update mechanism. No native activation, graphics or recovery result is claimed by fixture tests. Do not run it on the Windows host.

Build and test as a regular Linux/WSL user with the repository Go toolchain:

```sh
go test -race ./packaging/boot-branding/activation
go vet ./packaging/boot-branding/activation
go build -trimpath -buildvcs=false -o /tmp/andeiva-boot-activation ./packaging/boot-branding/activation
```

No new dependencies are introduced. Tests use isolated files and a private command substitute; they never invoke native boot tools. The real binary has fixed root `/`, fixed executables and no alternate-path/test mode.

Before approved execution, verify the experimental package and offline dependency closure, independent boot backup **before** installing Plymouth, recoverable snapshot and actual authorized recovery. Boot an alternative kernel or prove an independent recovery medium: rescue using only the initramfs about to be replaced is insufficient. Qualify the exact supported BIOS/Debian13/ext4 layout; other layouts are refused.

From the authorized root console, approved sequence: `andeiva-boot-activation preflight`, `andeiva-boot-activation prepare --recovery-verified`, then `andeiva-boot-activation apply`. The flag records an operator attestation, not an automatic recovery test. Inspect `andeiva-boot-activation status`: `pending-reboot` does not mean a verified boot. Reboot and service/network checks are separate operator-coordinated gates; this tool never reboots.

Use `andeiva-boot-activation restore` for a verified, unambiguous backup. It uses the prepared kernel's fixed targets even when running the fallback kernel. Unknown live changes, corrupted backups or an interrupted pending command with unobserved bytes cause refusal; retain evidence and use independent recovery. Do not delete backups or remove selected theme resources. One activation set is supported; there is no automatic backup cleanup.

After a complete restore, `prepare --recovery-verified` can rearm that same set when both kernels and all original/context/live hashes still match. It does not replace the original backups. A different context or any drift requires separate reviewed recovery, not deletion of the journal.

The menu stays visible for five seconds. Vendor `10_linux` is untouched, so ordinary loading lines can remain. No A/B, power-loss, full package rollback or completed branding guarantee is provided. See [design](../DESIGN.md) for paths, limitations and remaining native gates.

Normal boot uses `loglevel=3`: kernel emergency/alert/critical messages remain on the console, while ordinary errors/warnings stay in the kernel log for authorized diagnostics. Esc shows available text diagnostics; for full kernel output use a temporary diagnostic boot without `quiet`/`loglevel=3` or with a higher console loglevel. Recovery arguments are unchanged. No driver blacklist, skipped filesystem check or disabled logging is introduced. Filesystem-check output may remain before Plymouth starts; native observation is still required.

Normal boot uses `systemd.show_status=error`: successful unit lines are suppressed; failed-unit status and journals remain available. Inspect the actual console after Plymouth quits.

## Portable checks and temporary diagnostics

Storage eligibility follows the actual mount layout and reported filesystem block size, not a disk name or hypervisor. Parser fixtures are not evidence that Proxmox, physical servers or untested firmware have passed native qualification.

Only the authorized platform operator may use `andeiva-boot-activation apply --diagnostic-boot`, after restore and a newly acknowledged prepare. It sends the trace stream to `/dev/null` and retains a bounded, potentially sensitive buffer at `/run/andeiva-boot-plymouth-debug.log` when Plymouth exits. Do not enter credentials into Plymouth prompts during this laboratory test. Existing debug settings and a pre-existing log are refused. Runtime capacity is checked, not reserved across reboot.

After Plymouth has stopped, verify the fixed log is a regular root-owned file with mode 0600 and less than 1 MiB before collecting it privately. Never upload raw traces to Git, CI, ordinary administration or support bundles. Trace data may be incomplete. A further reboot can replace it. This does not change drivers, connectors, resolution, firmware or recovery arguments.

Diagnostic selection is persistent until the explicit sequence `restore`, `prepare --recovery-verified`, normal `apply` and a normal reboot. Switching modes while a configuration is pending is rejected; repeating the same apply is idempotent. Collect the trace first and retire the diagnostic selection before returning the appliance to ordinary use.

## Optional graphical compatibility

For an observed DRM presentation fault, after verifying recovery, use `restore`, `prepare --recovery-verified`, then `apply --redraw-compatibility`. This explicit mode adds the standard Plymouth redraw argument to normal boot only. It does not force a resolution or change drivers; default apply is unchanged. It cannot be combined with diagnostic boot.

Check a real reboot, complete logo/text, Esc diagnostics, service health and CPU/RAM cost. More frequent scanout resets can increase graphics work; a held preview alone is insufficient qualification. To remove the option, repeat restore and preparation, use ordinary `apply`, then reboot. No universal hardware compatibility is claimed.
## Pending offline installation

If `ANDEIVA_BOOT_OFFLINE_INSTALL_PENDING` is returned, do not retry activation or restoration and do not delete the marker just because a lock or PID disappeared. An interrupted dependency installation may have surviving package processes. Read-only `status` and root-only `capabilities` remain available. Use authorized local recovery to inspect the installer journal/backups and prove package processing has stopped before resolving the pending condition. No automatic package rollback or power-loss guarantee is provided.
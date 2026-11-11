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

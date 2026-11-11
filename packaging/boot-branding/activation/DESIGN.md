# BOOT-ACTIVATION-001: local experimental activation

Status: packaged activation and restart exercised in the Debian laboratory; visual defects found during operator review remain under correction. No power-loss qualification.

This increment is a local privileged operator tool, separate from the data package and administrative API. Production paths, commands and theme name are fixed. Test fixtures and command substitutes exist only in unit tests; there is no runtime alternate root, executable, kernel argument or command-string option.

Initial compatibility is deliberately narrow: Debian 13, BIOS, a writable ext4 root filesystem, `/boot`, `/etc`, `/usr` and backups on that root filesystem, an intact alternative kernel/initramfs, and installed/verified theme and Plymouth prerequisites. Other layouts, encryption, UEFI, serial boot, unsafe ownership/permissions and insufficient free bytes/inodes are rejected. This is not a general Debian installer.

## Operations

1. `preflight`: inspect without changing boot configuration. Missing Plymouth is a blocker; the tool never installs dependencies.
2. `prepare --recovery-verified`: operator attestation that an independent recovery path and recoverable snapshot are tested; create a serialized, protected backup set and bounded durable journal. Repeating preparation validates existing originals and backups instead of replacing them.
3. `apply`: verify prepared state and absence of drift; write the owned GRUB defaults drop-in, select the installed Plymouth theme without `-R`, regenerate only the running kernel's initramfs, then regenerate and syntax-check GRUB using supported tools. Preserve the visible five-second menu and recovery entries. Do not edit vendor `10_linux`.
4. `status`: report machine-readable phase; pending reboot is not a verified boot or healthy appliance.
5. `restore`: verify backup hashes and current-file ownership/fingerprints, then restore exact prior bytes or remove an owned newly created configuration. Restore itself is journaled and retryable. Do not overwrite unknown changes.

Only one activation set is supported. Completed backups are retained; no cleanup, kernel deletion, automatic reboot, kernel installation, network change or A/B conversion is provided. The pre-dependency boot backup remains separately required: a backup made after Plymouth installation cannot undo its package triggers.

After a complete restore, `prepare --recovery-verified` may rearm the same backup set only: kernel/alternative must match, backups/context/live hashes must verify, and every observed target must equal its original record. It changes only the journal phase to `prepared`; it does not replace backups or create a generic new activation set. Drift or a different kernel context is refused.

The four backed-up targets are `/etc/default/grub.d/99-andeiva-branding.cfg`, `/etc/plymouth/plymouthd.conf`, `/boot/grub/grub.cfg` and `/boot/initrd.img-<prepared-kernel>`. This is not full package rollback. Distribution tools can maintain their own temporary files, backup images and `/var/lib/initramfs-tools` stamps; their installed implementation and side effects require operator review before native use. A failed preparation or interrupted temporary journal write is not automatically cleaned up: preserve the private directory and use reviewed recovery rather than deleting protected backups.

## Integrity and interruption limits

Backups cover the owned drop-in (normally absent), Plymouth configuration, generated GRUB configuration and current initramfs. Read-only context hashes bind the default GRUB source and alternative kernel/initramfs. State contains fixed identifiers rather than arbitrary paths; strict decoding rejects unknown fields, duplicate identifiers and malformed hashes. Files and ancestor directories must be root-owned and not group/world-writable; symlinks and nonregular targets are rejected. A private lock serializes tool instances. Fixed command paths run with a clean environment and bounded output/time.

Observed hashes are updated only for the target that the current operation is allowed to change. The qualified layout requires `/etc/initramfs/post-update.d` to be absent: a present directory is refused, even when empty, because its hooks can regenerate GRUB or have other unqualified effects. The initramfs step therefore permits only its current image; selecting Plymouth permits only its own configuration. An unrelated target mutation is refused rather than adopted as the tool's output. The local G204 exception applies solely to `update-initramfs -u -k <kernel>`: fixed executable/flags, strict kernel validation, protected-journal/running-kernel binding and separate argv, without a shell. Contract and negative argument tests preserve that boundary; there is no global suppression.

Each mutation has durable intent before execution, then observed hashes after completion/failure. These commands are not an atomic transaction across files. If a process dies while a command is pending and live bytes match neither a recorded before nor observed after hash, automatic restoration refuses the ambiguous state and requires independent local recovery with the retained backups. A safe refusal is not successful automatic rollback. No claim of power-loss resistance, absolute disk availability or A/B recovery is made.

The installed GRUB generator's `quiet_boot=0` has no supported override established here. Ordinary kernel/initramfs loading lines may remain. The menu is kept visible; this increment does not meet the final message-free branding acceptance criterion. Existing authentication, diagnostics and prior kernels remain in place. No Web/CLI reboot integration is implemented.

Normal entries append `quiet splash loglevel=3 systemd.show_status=error` through `GRUB_CMDLINE_LINUX_DEFAULT`, preserving prior arguments and leaving recovery-specific arguments unchanged. Kernel console output retains emergency, alert and critical priorities; ordinary errors and warnings are not printed there. Kernel logs remain available to authorized diagnostics. No driver is blacklisted, filesystem check skipped, logging disabled or failure result changed. Esc exposes available Plymouth text diagnostics; detailed kernel troubleshooting also requires a temporary diagnostic boot with `quiet`/`loglevel=3` removed or an explicitly higher console loglevel. This does not suppress initramfs/fsck stdout or prove that all normal text is invisible; actual Plymouth start order requires native observation.

## Required evidence

Pure tests must cover clean preparation, idempotence, command ordering, current-kernel-only initramfs generation, drift, unsafe metadata/links, capacity rejection, malformed state, interrupted steps, command failures, restoration and concurrency. Native gates remain: offline dependency closure/triggers, alternative-kernel or independent recovery rehearsal, activation, cold boot/reboot/shutdown, resolution and diagnostics, service/network invariance, update and restoration. Measure package/initramfs bytes, elapsed time and peak memory/CPU; no active measurements are claimed by fixture tests.

Normal boot uses systemd.show_status=error to suppress successful unit-status lines while retaining failed-unit status. Journals, filesystem checks and recovery boot arguments remain enabled. Native validation must check the handoff after Plymouth quits; a successful theme load alone does not establish a clean console.

## Platform-independent design and qualification

Device labels, hypervisor names, connector names, fixed monitor resolutions and GPU drivers are not activation criteria. Mount topology, filesystem type, reported block size, firmware, console, available capacity and verified recovery determine eligibility. Device-name fixtures cover SATA/SCSI, virtio, NVMe, mapper and root aliases; these are simulated parser cases, not native platform certifications.

The current native evidence comes from one Debian 13 AMD64 BIOS laboratory. Proxmox/KVM, physical servers, UEFI/Secure Boot, separate boot filesystems and ARM64 require their own installation, rendering and recovery evidence. Untested layouts remain gated; the portable architecture does not imply they have passed.

## Explicit diagnostic boot

Only `apply --diagnostic-boot` adds both fixed Plymouth debug parameters to normal entries: stream to `/dev/null` and buffered dump to `/run/andeiva-boot-plymouth-debug.log`. It refuses existing debug settings, a pre-existing log, unsafe runtime paths and insufficient tmpfs capacity. No graphical driver, connector, resolution or GRUB video payload is forced. Normal and diagnostic pending configurations cannot silently replace one another.

The pinned Plymouth implementation retains less than 1 MiB of buffered trace and may discard earlier messages. Its dump truncates the destination on quit/root transition; creation uses mode 0600. Traces are potentially sensitive, including interactive question answers: use only the authorized unencrypted laboratory without entering credentials into Plymouth prompts. Read after Plymouth has stopped, validate regular-file type/root ownership/0600/size, and collect privately. Never include raw traces in Git, CI, ordinary administration or support exports. Capacity checks are not a reservation across reboot. Diagnostics do not promise evidence after power loss or SIGKILL.

This mode remains selected until restore, prepare and normal apply. Collect evidence before another reboot can replace it, then retire the diagnostic selection. It is not an automatic remediation, a complete trace guarantee or a completed graphical-boot fix.

## Optional redraw compatibility

`apply --redraw-compatibility` appends only the upstream Plymouth argument `plymouth.set-mode-on-redraws` to normal boot entries. It asks the DRM backend to reset scanout during redraws; it does not select a GPU, connector or resolution, replace a module, disable udev or change recovery arguments. Default activation is unchanged. Diagnostic and compatibility modes are mutually exclusive; pending configurations must match exactly before an apply can be repeated.

Use this explicit option only after reproducing a graphical presentation fault and qualifying the result on the target platform. Repeated scanout resets can increase CPU and graphics work. A successful held preview does not establish cold-boot, shutdown, keyboard, recovery or cross-platform support. Measure those separately. Restore, acknowledge preparation again and apply the required mode to switch; ordinary apply removes the option after that sequence. Never deploy the private renderer-masking diagnostic as a product workaround.
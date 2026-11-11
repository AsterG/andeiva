# BOOT-BRANDING-001: inactive resource increment

## Scope and dependencies

This increment supplies an `Architecture: all` data package, GRUB template, Plymouth script, original decorative assets and integrity checks. It does not introduce an installer or activation helper. Existing Debian installation is not converted to immutable A/B storage. No Web/CLI power operation is added.

The exact logo remains a complete 2:1 image on a light branding surface. GRUB displays a separate deterministic 320x160 proportional copy. Its 2.12 image widget imposes the bitmap dimensions as a minimum, so width/height alone cannot safely shrink the original. The original remains byte-identical in both directories; only the separate display copy is downsampled. Plymouth recomputes uniform scaling when display dimensions change. Decorative background scaling does not change logo pixels. Initial qualification targets are 800x600, 1024x768, 1280x720 and 1920x1080; they are **test targets**, not supported hardware claims. Serial/headless and unavailable graphics must retain independent text recovery.

Plymouth's reported mode selects English startup, reboot, shutdown or update text. Unknown modes show `System activity...`. No timer produces a progress percentage or successful state. There is no `SetBootProgressFunction` callback. Password input is masked, prompts/messages are preserved, and the activity indicator pauses during prompts. Existing label/font support must work before activation; no external font fetch is allowed. Detailed diagnostics via Esc and full-width/long diagnostic text require real console tests.

## Audit conclusions and unresolved dependencies

- No existing boot theme implementation was available to reuse. The native appliance package remains separate.
- The inspected Debian GRUB generator assigns `quiet_boot="0"` internally, so changing menu titles alone does not suppress its ordinary kernel/initramfs loading messages. A supported mechanism has not been established. Do not patch generated `grub.cfg`, globally suppress `echo`, or overwrite `10_linux` to hide this gap. A controlled generator adaptation would require a separate approved design with integrity and package-upgrade checks.
- Plymouth, script/renderer/label components and graphics must be qualified from signed offline packages. Installing these dependencies can itself trigger initramfs generation; recovery preflight and backup must happen **before** such installation.
- Theme data does not rename menu entries or hide the menu. A future qualified activation step must preserve prior kernels, recovery entries, record-failure behavior and a usable menu timeout/key path. Do not set zero timeout or disable recovery.
- Local restricted-console branding and typed authenticated Web/CLI power operations are separate dependencies. Current resources do not imply either is implemented.

## Affected paths

| Package path | Purpose | Activation effect |
| --- | --- | --- |
| `/usr/share/grub/themes/andeiva/` | GRUB template, background, exact logo | None until explicitly selected |
| `/usr/share/plymouth/themes/andeiva/` | Plymouth script, descriptor, background, exact logo, activity images | None until explicitly selected and included in initramfs |
| `/usr/share/doc/andeiva-boot-branding/` | License, notices, design and EN/ES/PT guides | None |

No fonts, shell binaries, configuration drop-ins, maintainer scripts or update hooks are shipped. GRUB's existing Unifont and Plymouth's existing label/font stack are prerequisites rather than bundled assets. Removing inactive resources removes only package-owned data; once activated, resources must remain installed until a separately validated deactivation and initramfs/GRUB restoration completes.

## Threat and recovery analysis

| Risk | Required protection and evidence |
| --- | --- |
| Untrusted theme or modified logo | Fixed payload allowlist, root-owned data, exact logo hash, checksum inventory, signed offline distribution; checksum alone is not authenticity |
| Hidden failure or password prompt | No diagnostic filtering, no fabricated success, preserve prompts and Esc/text recovery; test failing service, encrypted prompts and broken graphics before activation |
| Loss of boot access | Authorized local console, recoverable snapshot, verified backup and an actual previous-kernel/recovery rehearsal before changing dependencies, GRUB or initramfs |
| Partial activation or exhausted storage | Space and inode preflight on every affected filesystem; retain an untouched prior kernel/initramfs; bounded durable activation journal and interrupted-stage tests required |
| Package upgrade overwrites local changes | Record ownership/hashes, refuse ambiguous restore, retain operator edits, qualify generator/kernel upgrades; no generated-file editing |
| Boot menu editing bypasses administration | Explicit physical-console threat model and individually provisioned GRUB authentication; no universal secret or Secure Boot change |
| Misleading availability claim | Separate resource/static checks from real boot/recovery/traffic evidence; no A/B or power-loss guarantee for existing Debian |

Future activation must be serialized, explicit, offline and idempotent. Its states should distinguish prepared backup, staged configuration, pending reboot and verified boot. GRUB and initramfs changes are not one atomic filesystem transaction. Restoration must detect external edits, preserve the backup and recover an untouched prior kernel rather than overwrite arbitrary paths. No activation script is included until these gates and the ordinary-message suppression design are reviewed.

## Acceptance and measurement

Implemented checks: deterministic asset generation, protected output files, serialized publication, exact packaged logo, fixed paths and permissions, exact package metadata fields, complete nonduplicated checksum inventory, no install hooks/dependencies, English authored strings, no percentage callback, required prompt/message callbacks, reproducible data packages and negative mutation checks. Archive inspection limits decompressed bytes and elapsed time before parsing members, then limits member count and payload size incrementally; rejected decompressor processes are terminated and reaped. These are development artifact checks, not a customer update/signature verifier.

Pending real evidence: theme parsing/rendering by installed GRUB/Plymouth; cold boot, reboot and shutdown; update mode; diagnostics and long prompts; authenticated recovery; missing renderer/framebuffer; serial console; locale and web-theme independence; each resolution and mode change; kernel upgrade; failed/interrupted activation and restoration; safe uninstall after deactivation; unchanged network/SSH/API/nftables behavior. Reboot through Web/CLI remains blocked on the separate power-operations contract.

Measure package and installed bytes, initramfs growth, comparable boot time, Plymouth peak RSS/CPU and any shutdown delay. This data increment installs no daemon or timer. It has no runtime activity while unselected; **active Plymouth CPU/RAM and boot cost are unmeasured**. Static checks or a preview image cannot close these gates.

## Primary technical references

- [GNU GRUB 2.12 manual](https://www.gnu.org/software/grub/manual/grub/grub.pdf): theme, menu, recovery and authentication mechanisms. Validate against the actual installed generator.
- [Debian Plymouth source](https://deb.debian.org/debian/pool/main/p/plymouth/): script callback/mode APIs inspected in upstream 24.004.60, including `themes/script/script.script` and `script-lib-plymouth.c`. API inspection is not a native execution test.
- [Debian Plymouth guidance](https://wiki.debian.org/plymouth): graphics and early-boot integration prerequisites.

GRUB geometry tests model minimum dimensions and independent viewport clamping at 640x400, 640x480, 800x600 and 1280x800. They reproduce the original oversized-image defect and reject menu/heading overlap; they are not a native GRUB renderer. Recovery navigation and final visual acceptance require real console evidence.

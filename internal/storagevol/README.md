# Inactive laboratory storage volumes

This development component prepares four **inactive** regular-file ext4 images.
It has no appliance integration, mount, activation, migration, cleanup command,
listener or background process. It does not close AND-01/AND-02 or prove continued
traffic enforcement under storage pressure. The official administrative CLI is
`andeiva`; `andeiva-storage-lab` is a root-only development tool.

## Fixed test profile

| Domain | Image capacity | Inodes requested |
| --- | ---: | ---: |
| Configuration | 128 MiB | 8192 |
| Protected audit | 128 MiB | 4096 |
| Observations | 64 MiB | 1024 |
| Recovery | 64 MiB | 2048 |

Total image capacity is 384 MiB. Filesystem metadata and journals consume part of
each image; this is not usable free space or a supported product sizing profile.
The preparation requires an additional observed 64 MiB of backing-filesystem
headroom and 64 free inodes. This check is admission, not a quota or reservation
against concurrent external writers.

Guest-filesystem block allocation is mandatory: no sparse/truncate fallback.
The formatter uses inherited FD 3 of the newly created exclusive regular image,
never an operator-supplied pathname or block device. Its path is fixed at
`/usr/sbin/mke2fs`; root-owned ancestors and permissions are enforced. The operator must verify
package provenance independently on the target. The environment is fixed. Formatting
uses `nodiscard,lazy_itable_init=0,lazy_journal_init=0` and one `-F` flag.
See the upstream [mke2fs manual](https://man7.org/linux/man-pages/man8/mke2fs.8.html).

After formatting, bounded read/write passes preserve all image bytes while
materializing reserved ranges, followed by synchronization. Ownership, size,
link count, allocation, expected superblock fields and SHA-256 are checked.
Manifest selection uses atomic no-replace rename and directory synchronization.

This is allocation visible to the backing ext4 filesystem, not proof of physical
capacity below thin provisioning, host snapshots or media. No claim covers backing
filesystem corruption, hardware failure, malicious root writers or power loss.
Preparing independent files alone does not enforce active service isolation;
private mounts and runtime wiring still require separate native evidence.

## Build and prepare

Build without root using the repository's pinned Go toolchain:

```sh
go test -race ./internal/storagevol ./cmd/andeiva-storage-lab
go vet ./internal/storagevol ./cmd/andeiva-storage-lab
go build -trimpath -buildvcs=false -o /tmp/andeiva-storage-lab ./cmd/andeiva-storage-lab
sha256sum /tmp/andeiva-storage-lab
```

Transfer only the reviewed binary and compare its externally retained checksum.
The native preparation is restricted to root UID/GID 0, Debian 13 AMD64, with an
ext4 backing filesystem. It does not install packages or change filesystem flags.
The acknowledgement flag records operator intent; it is not authentication or a
proof of laboratory ownership. An authorized operator and recoverable laboratory
are required before running:

```sh
andeiva-storage-lab --authorized-debian-lab --operation plan
andeiva-storage-lab --authorized-debian-lab --operation prepare
andeiva-storage-lab --authorized-debian-lab --operation inspect --id PREPARED_ID
```

`PREPARED_ID` is the exact 32-character lowercase hexadecimal ID returned by
`prepare`. The fixed base is `/var/lib/andeiva-storage-lab`; there is no path or
size override. A single existing preparation, including an incomplete one, blocks
another preparation. Unknown files, links, changed ownership and malformed
manifests are refused without deletion. Exceptions are stable machine codes;
help is available through `--lang en|es|pt --help`.

Preparation errors retain their owned partial workspace. An ambiguous final
publication returns `ANDEIVA_STORAGE_VOLUME_UNCERTAIN`, not success. Authorized
read-only inspection can verify a complete, original preparation after process
interruption. Inspection checks initial image hashes: images changed by a later
mount/write test are intentionally rejected rather than silently re-baselined.

## Native isolation and cleanup gates

Root coordinates privileged native tests through the existing
`packaging/preview/tests/storage-pressure.sh` private mount/network namespace
harness. Do not mount these images on a shared CI runner or introduce another
privileged harness. Required extension evidence includes distinct filesystem
identities and budgets, filling observations by bytes/inodes, and unchanged free
space for configuration/recovery. Actual ENOSPC/EROFS/EDQUOT and data-plane
continuity are separate gates, not implied by unit tests.

The tool has no deletion operation. The authorized harness/operator must first
verify that every test image is unmounted and detached, retain evidence and remove
only that explicitly owned, inactive test set. Never recursively delete arbitrary
paths or use this procedure for live configuration/protected audit. Existing
appliance data, interfaces, routes, boot settings and services are untouched.

Unit tests use real file allocation with a **simulated formatter signature**;
they do not create mountable ext4 images. Tests cover no-replace publication,
partial preparation, actual child exits, changed images, links/FIFOs, permissions,
malformed manifests, bounded arguments and unrelated-file preservation. Native
mke2fs formatting, mounts, resource measurements and all lower-storage failure
claims remain pending until separately reported. The small benchmark measures a
16 MiB signature fixture, not native formatting or sustained appliance capacity:

```sh
go test ./internal/storagevol -run '^$' -bench '^BenchmarkInactivePreparation$' -benchtime=3x -benchmem
```

See [Español](docs/es.md) and [Português](docs/pt.md).
## Selection and threats

Project quotas could bound selected directories, but require support and correct
accounting on the existing filesystem; they do not create independent free-inode
pools or protect against unrelated root writers. This experiment instead prepares
fixed-size files for separate ext4 filesystems, with independent byte/inode
budgets once mounted by the authorized harness. It does not repartition or remount
the appliance root. A future production design still needs filesystem placement,
recovery reserves, protected-audit retention and lower-storage failure evidence.
Threat checks cover foreign paths, symlinks, hardlinks, concurrent preparation,
partial files and uncertain manifest publication; malicious root is out of scope.

## Optional native copied-volume pressure test

The existing storage-pressure harness has an additional explicit opt-in mode.
It requires the root-owned test runner, its SHA-256, the inspector and its SHA-256,
and a successfully inspected preparation ID. Existing four-argument tmpfs mode
is unchanged. Build both binaries without root:

```sh
CGO_ENABLED=0 go test -c -o /tmp/storagevol.test ./internal/storagevol
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /tmp/andeiva-storage-lab ./cmd/andeiva-storage-lab
sha256sum /tmp/storagevol.test /tmp/andeiva-storage-lab
```

Transfer reviewed binaries/harness to a root-owned directory with non-writable
ancestors and compare checksums. On the authorized Debian laboratory as root:

```sh
bash /root/storage-pressure.sh --authorized-debian-volumes \
  /root/storagevol.test RUNNER_SHA256 --isolated-storage-only \
  /root/andeiva-storage-lab INSPECTOR_SHA256 PREPARED_ID
```

Replace all uppercase placeholders with the verified values. `harness-plan` is a
read-only, fixed-field encoding of `inspect`; it cannot supply arbitrary paths.
The harness verifies the original images, copies all 384 MiB without reflinks or
sparse copying, and mounts only the copies in private mount/network namespaces.
It requires 512 MiB of available backing headroom before copying. Original images
plus copies consume 768 MiB, excluding small executables/metadata. The fixed copy
base is `/var/lib/andeiva-storage-pressure`; an existing workspace blocks reuse.

The native test fills observations by bytes and by inodes, checks EROFS, and
verifies that an unlinked open file retains blocks until close. Configuration,
audit and recovery free-block/free-inode counts must remain unchanged during each
pressure event; configuration and recovery must still pass write/fsync probes.
These are isolated filesystem tests, not appliance/data-plane continuity tests.
The harness unmounts, detaches and checks copied images before removing only its
own files; any cleanup failure retains the workspace for authorized recovery.
No lazy unmount, forced detach, original-image deletion or protected-audit
retention change is implemented. Native success must be recorded separately;
ordinary unit/CI runs skip the privileged test and never mount anything.

The harness rejects runners/inspectors larger than 32 MiB and scripts larger than
128 KiB before hashing/copying. Each case captures bounded root-only logs and
requires actual RUN/PASS output; native cases additionally require an exact
completion marker emitted after all assertions. Exit zero with "no tests" is a
failure. On test failure, safely detached copies and logs remain for authorized
recovery, and another run is refused. Success removes its own logs and copies.
The log-gate regression runs without root or mounts:

```sh
bash packaging/preview/tests/storage-pressure-log-test.sh
```

Native qualification on Debian 13 AMD64 passed for the reviewed implementation:
384 MiB of inactive images were fully allocated and all four passed read-only
filesystem checks. Preparation took 3.641 s elapsed / 3.616 s CPU. The copied-volume
harness passed ENOSPC (bytes and inodes), EROFS and open-deleted-file checks in
3.415 s elapsed / 3.023 s CPU; peak cgroup memory was 490,237,952 bytes including
filesystem cache/slab, not process RSS. Originals remained unchanged and copied
mounts/loops were removed. These isolated tests do not qualify appliance continuity
or close AND-01/02. Full logs and target identities remain outside this repository.

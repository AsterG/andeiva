# Preallocated recovery pool

This internal primitive prepares 1–32 fixed files with two aligned, preallocated
banks of 4 KiB–1 MiB payload each. Linux `fallocate` and allocated-block checks
are required; sparse-file fallbacks are refused. Exclusive locking and pinned
owner/mode/device/inode checks protect the borrowed private `os.Root`.

`Claim` durably assigns a slot to an operation. `Write` compares its process-local
lease, writes the inactive payload, syncs, publishes a checksummed header and
syncs again. Ambiguous failures fence that handle. No mutation creates a path,
inode or unbounded log. Claims are not recycled by age or caller assertions.

The owning transaction engine must persist the exact `Binding` with its intent.
Only `ReadBound` verifies that pool, slot, owner, sequence and payload digest.
`Read(owner)` can return an older intact bank for diagnostics/recovery; it is
**not** evidence that a selected transaction completed. A damaged first claim
cannot be mistaken for unused space. Corruption is detected, not authenticated
against a malicious storage owner; checksums are not signatures.

The pool is not yet integrated with configuration publication or protected audit.
It has no retirement, garbage collection, deletion, mount or network API. A
coordinator must qualify ownership, consumption, recovery and authorized return
before enabling it. Existing appliance startup and configuration remain unchanged.

## Reproduce

With the repository's Go version installed:

```sh
go test -race ./internal/recoveryreserve -count=3
go vet ./internal/recoveryreserve
GOOS=linux GOARCH=amd64 go test -c ./internal/recoveryreserve -o reserve.test
sha256sum reserve.test
```

On a disposable Debian 13 lab with console and recovery snapshot, copy that
binary and the repository. As root, install the binary in a root-owned private
directory, then explicitly run:

```sh
bash packaging/preview/tests/recovery-reserve-pressure.sh \
  --qualify-isolated-ext4 /absolute/root-owned/reserve.test SHA256 andeiva
```

Replace `SHA256` with the verified lowercase digest and `andeiva` with an existing
non-root laboratory account whose primary group has the same name. The harness
uses private mount/network namespaces, a new 64 MiB ext4 image and dropped
privileges. It verifies byte/inode exhaustion, then claims/writes/reopens and
checks an exact binding. It unmounts the disposable filesystem, retaining the
qualification directory for inspection. Privileged tests do not run on shared CI.

Process-exit tests are not power-loss tests. `fallocate`, physical block counts
and this ext4 test do not guarantee metadata/journal/COW capacity on every device
or filesystem. Runtime integration, quota isolation, RO/EIO/EDQUOT qualification,
authorized retirement and live enforcement continuity remain separate gates.
Native Debian 13 tests passed actual byte and inode exhaustion on an isolated64MiB ext4 image using UID1000 with no capabilities. Exact final binding/reopen test elapsed0.62s; combined preparation/test CPU0.414153s/cgrouppeak74,477,568B includes formatter and filesystem cache. Full native pool regression passed separately with CPU0.049284s/cgrouppeak16,248,832B. These are fixture observations, not daemon RSS, universal allocation guarantees or appliance continuity qualification.

Shared-profile reads retain separate process identities: `ReaderAccessV2.ReadFile` requires the dedicated helper reader group; `ReadOwnedFile` requires the exact non-root owner. Both use identical bounded, pinned-directory, UID/GID/mode/ACL and no-follow checks. The API does not join the helper reader group. These primitives grant neither a writer lock nor authority to apply policy.

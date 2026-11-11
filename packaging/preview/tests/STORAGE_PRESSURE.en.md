# Finite storage laboratory checks

Run only on an authorized, recoverable Debian 13 AMD64 laboratory. This harness
requires root, `unshare`, mount tools and the existing `andeiva` UID/GID 1000.
It creates private mount/network namespaces and three disposable 16 MiB tmpfs mounts
with 256 inodes. It does not change appliance services, existing network namespaces,
interfaces, routes or firewall rules. Never fill the host filesystem for this test.

Build the test executable on a development machine from the reviewed source:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -trimpath -buildvcs=false -o configpoc-storage.test ./internal/configpoc
sha256sum configpoc-storage.test packaging/preview/tests/storage-pressure.sh
```

Transfer both files through an authorized medium and verify their recorded
checksums independently. From the laboratory console, create a fresh root-owned
input directory under a trusted root-owned tree (such as `/root`) and install the executable as mode 0555 and harness as 0500.
Run with absolute paths and the executable's verified SHA-256:

```sh
bash /ABSOLUTE/ROOT_OWNED/storage-pressure.sh --authorized-debian-lab /ABSOLUTE/ROOT_OWNED/configpoc-storage.test VERIFIED_SHA256 --isolated-storage-only
```

Expected: bytes, inodes and readonly cases pass, followed by
`ANDEIVA_STORAGE_LAB_RESULT=pass`. Byte/inode cases exercise ordinary admission,
read availability and recovery after removing only their own filler files.
Readonly checks the real read-only probe; it does not boot an already read-only
configuration store. The harness unmounts its tmpfs and removes its empty test
directory. If unmount fails, do not recursively delete that path; inspect the
reported mount namespace and stop the test process before cleanup.

The tests use simulated configuration engines, not packet traffic. They prove
bounded filesystem behavior, not disk quotas, physical reservation, power-loss
safety, protected audit retention or permanent dataplane continuity. A free-space
observation can become stale; actual write/fsync failures still require recovery.
Keep these gates open even when this harness passes. No privileged storage test
runs on shared CI runners; CI checks syntax, unit tests and platform compilation.

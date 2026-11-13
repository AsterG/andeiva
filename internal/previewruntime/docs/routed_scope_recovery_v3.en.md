# Root scope recovery prerequisites

This experimental increment does not recover a crashed supervisor yet. It adds
creation-time anchor capture, an exact 4096-byte root operational record, a
read-only descriptor constructor and actual system-manager store readback. It
never unmounts, deletes a path, closes the lease gate or writes a retirement
receipt. Selected G1/R2 authority remains separate and mandatory.

`PrepareRoutedScopeRecoveryRecordV3` requires real root, the current BootID/host,
the current mount namespace and exact dedicated cgroup with no other process.
The caller supplies six read-only descriptors: preallocated record, gateway net
namespace, mount namespace, original pre-bind underlay, root 0700 namespace
directory and cgroup2 directory. The record binds their device/inode identities,
metadata digest and service identities. Root must persist/fsync it before L2
creation or enablement. A checksum detects torn bytes; it is not authentication.

`OpenRoutedScopeRecoveryV3` verifies root file ownership/mode/allocation, exact
encoding, descriptor access/type/identity, nonhost scope and current BootID. It
duplicates accepted descriptors with CLOEXEC. `VerifyStored` runs a fixed bounded
`busctl` status query and requires exactly the six named descriptors, comparing
mode, device, inode and open flags. Paths and ordering do not establish identity.
The record and descriptors are checked again after readback. A successful query
proves retention only; it does not prove drainage or authorize receipt issuance.

The next integration must publish descriptors with FDSTORE and verify acceptance
before L2 effects; acquire named inherited FDs at the next MAIN invocation while
separating the management socket; prove the retained original cgroup drained;
tear down the exact old scope through the retained mount namespace; release the
manager's copies and verify their absence; then issue the existing root receipt.
A missing pin, renamed unit, empty replacement cgroup or manifest alone is never
proof. An offline/deleted old cgroup remains blocked until its drainage proof is
implemented. Normal shutdown must also release manager-held copies before a
receipt. Partial publication or teardown must retain evidence and block restart.

Proposed unit changes, not applied: `NotifyAccess=main`,
`FileDescriptorStoreMax=6`, `FileDescriptorStorePreserve=yes`. Recovery belongs in
the next main startup: do not assume ExecStopPost receives stored descriptors.
FD names are fixed and disclose no policy, credential or selected-work digest.
No dependency, unit, host network or appliance was changed. These constructors
alone do not close the crash-recovery gate; native SIGKILL/stop/start, inherited
FDs, mount teardown, injected partial failures and resource measurements remain
pending. There is no reboot, suspend or power-loss claim for retained FDs.

Tests cover exact encoding, altered scope/phase, aliases, torn records, writable
or wrong-type descriptors, unprivileged refusal and incomplete/duplicate/changed
manager readback. Manager replies in tests are explicit doubles, not native
systemd evidence.

```sh
go test -race ./internal/previewruntime -run TestRoutedScopeRecoveryV3 -count=1
go vet ./internal/previewruntime
go build ./internal/previewruntime
```

The design follows [systemd257 service FD-store lifecycle](https://www.freedesktop.org/software/systemd/man/257/systemd.service.html)
and [named descriptor inheritance](https://www.freedesktop.org/software/systemd/man/257/sd_listen_fds.html).
A [notification barrier](https://www.freedesktop.org/software/systemd/man/257/sd_notify.html)
synchronizes processing, not successful storage. Readback uses the fixed
[systemd257 DumpUnitFileDescriptorStore protocol](https://github.com/systemd/systemd/blob/v257/src/analyze/analyze-fdstore.c).

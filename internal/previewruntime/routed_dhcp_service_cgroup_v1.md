# DHCP service process scope, version 1

Development component under ADR-062. It does not qualify DHCP WAN, permit a listener, open forwarding, or change the public API, CLI or web contract.

The trusted supervisor creates a new child cgroup for each acquisition-service incarnation before launching its producer. The producer and its descendants inherit that membership. Existing groups are never adopted. The private bootstrap requires service version 1, the kernel device/inode identity and a ninth inherited descriptor (FD 11), opened read-only. Profiles 3 and 4 retain their operation semantics; mixed bootstrap implementations fail closed. The receiver verifies the pin, exact incarnation, membership and absence of other child groups before preparing private mounts.

`RetainedServicePin` returns an independent, caller-owned read-only duplicate and its identity. The supervisor must obtain it before closing the owner when later observation needs to retain the old origin. `Close` preserves the existing graceful shutdown, then requests cgroup-wide termination and checks `populated=0` within a separate three-second drain budget before removing that exact directory. Failed identity checks or drainage retain the error and owned group resources. No recursive deletion or arbitrary process adoption is used.

Process drainage does **not** prove socket absence or continued socket possession. A transferred socket can outlive its creator. The future observer must retain the old pin and reject residual sockets until complete physical readback proves absence; it must not reuse that origin. Read-only descriptors are an inventory boundary, not a sandbox for the trusted root producer. No listener exception is enabled by this component.

This introduces no daemon, timer or service when DHCP acquisition is unused. Native acquisition, capability qualification, disable/readback integration, security review and CPU/RAM measurements remain separate gates. There are no installed-unit, capability, host-network, dependency or container/Helm changes. This Linux appliance component requires cgroup v2, creation rights limited to the dedicated supervisor scope, `CLONE_INTO_CGROUP`, and `cgroup.kill`; it does not claim compatibility with arbitrary containers.

## Validation

```sh
go test -race ./internal/previewruntime -run 'TestRoutedDHCP(Service|Owner|Deferred|Initial)' -count=1
go vet ./internal/previewruntime
go build ./internal/previewruntime
GOOS=windows GOARCH=amd64 go build ./internal/previewruntime
```

The opt-in `TestNativeRoutedDHCPServiceCgroupV1` is for an authorized, otherwise unused laboratory supervisor unit only. It checks real child placement, multi-process drainage, refusal to adopt an existing group and the independent pin after removal. It performs no network operation and does not test DHCP or socket ownership. Normal tests skip it. Native execution and resource results must be recorded independently before any qualification claim.

## Source change

Added an exclusive acquisition-service process scope, required private bootstrap pin and explicit retained-pin API. Shared release tracking is maintained by the orchestrator.

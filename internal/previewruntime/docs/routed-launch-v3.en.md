# Grouped runtime launch V3

This Linux library connects the existing V3 factories in separate processes. It is an experimental integration component, not a deployment command or a production readiness claim.

The trusted root supervisor calls `StartRoutedLaunchV3` with pinned isolated namespace descriptors, a helper-owned socket directory, the API-owned selected store and three provisioned reserve pools. It retains those resources until `Close` returns. The binary dispatches only `RoutedHelperRoleV3` and `RoutedAPIRoleV3` to `RunRoutedLaunchRoleV3`, then exits when that function returns.

The API stays in the host namespace with no capabilities. The helper enters the isolated gateway with only `CAP_NET_ADMIN`. Its dedicated supplementary reader group differs from both IPC and API groups. The network executor uses `NewInOwnedNamespaceWithReader` with that trusted reader group and both namespace pins; the older constructor keeps its original group restrictions.

Inherited descriptors are fixed: 3 gateway namespace, 4 helper socket directory, 5 selected store, 6 admission pool, 7 plan pool, 8 emergency pool, 9 bootstrap pipe, 10 control pipe, 11 event pipe, 12 host namespace. Namespace descriptors and directories are read-only. Pipes are root-owned. Each slot is validated before roots are reopened; aliases, inappropriate types and access modes are rejected. Bootstrap is bounded and binds the root parent, boot, namespaces, identities and resource profiles.

The helper factory supplies the existing routed authority and `NewRoutedCompatibilitySessionV2` session. The API factory supplies `OperationsRuntimeOptionsV2`, using the inherited store and matching shared-reader profile. It must not open a configuration writer before `OpenRoutedOperationsRuntimeV3`. Both factories own only the additional resources returned through `Cleanup`.

The helper creates Unix sockets after dropping privileges. Each side checks the actual peer UID, GID and PID; a root-created inherited socket pair is not used. `ServeAPI` receives the opened runtime and a `ready` callback. It binds its trusted TLS listener after boot/resume and readback, calls `ready` exactly once, and returns promptly on cancellation. A helper-ready event alone never means the API is ready.

`RestartAPI` reaps the previous API, drains its helper channels without cancelling an in-flight effect, and only then releases the new API bootstrap. The existing V3 handshake advances the controller fence before the new writer opens. The helper and its guardian remain alive. A failed restart blocks further restarts in that supervisor. Recover by closing it and using the approved fixture recovery procedure.

`Close` stops and reaps the two direct children. Helper loss also stops the API. Parent-death signals are installed while the spawning OS thread remains alive. The caller still owns isolated fixture cleanup and must prove descendant termination before removing namespace resources. This library does not provide a cgroup, provision interfaces, activate host services or claim complete descendant cleanup.

Validation commands from the repository root:

```sh
go test -race -p 1 ./internal/previewruntime ./internal/networkexecutor -count=1
go vet ./internal/previewruntime ./internal/networkexecutor
go build ./...
```

The focused tests cover fixed privilege arguments, bounded events, controller PID rejection, drain/fence sequencing and reader-group restrictions. Same-process Unix tests do not prove the separate-process privileged bootstrap. Native three-process factory wiring, inherited-descriptor negatives, process-loss recovery, descendant cleanup and CPU/RAM measurements remain separate acceptance gates. Docker/EKS deployment is not supplied by this increment.

The helper factory must use `NewRoutedReadbackSessionV3` with the same concrete
group authority. Compatibility no longer owns a second guardian. Its scoped
bootstrap means verified legacy-table absence only; idle means that a complete
trusted legacy revision matched physical readback. Neither is group readiness,
confirmation or permission to write. The runtime and complete Group readback
remain mandatory before API readiness. Reads are serialized with physical
application; unknown policies, failed captures and transient deny policies are
not accepted as selected revisions. Counter epochs change before every attempted
table application, including uncertain results and restoration. Epoch exhaustion
denies compatibility readback rather than wrapping, without preventing rollback.

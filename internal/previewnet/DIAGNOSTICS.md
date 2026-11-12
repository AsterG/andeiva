# Privileged preview lifecycle diagnostics

The root-only namespace supervisor records bounded `failure` and `cleanup_failure` events in its existing privileged service journal. Each event contains only allowlisted `phase`, `check` and `code` categories. It does not include the raw error, command output, namespace, route, path or credentials. Ordinary command failures and administrative API responses remain generic.

The first runtime failure category is captured in bounded memory before cleanup. Diagnostic output occurs only after cleanup, so a blocked log writer cannot prevent resource removal. A separate cleanup failure cannot replace the original category. Each process emits at most one of each; there is no retry loop or event history in memory. Host baseline, sentinel, listener checks, deadlines and recovery preconditions are unchanged. Residual state still requires the existing authorized recovery procedure; these events do not authorize deletion or automatic restart.

A phase identifies where a failure was observed, not its underlying cause. For example a listener check deadline does not prove a dead listener. Historical incidents without these records cannot be diagnosed retrospectively from a generic failure alone. Access to this journal remains a privileged operational responsibility; these diagnostics must not be added to ordinary UI, exports or support bundles.

Run the nonprivileged regression tests on Linux with Go 1.27.4:

```sh
go test -race ./internal/previewnet ./cmd/andeiva-preview -count=3 -timeout=4m
go vet ./internal/previewnet ./cmd/andeiva-preview
go build ./cmd/... ./internal/...
```

Tests use fake health checks and real command error formatting; they do not create network namespaces or alter host settings. They verify check ordering, context identity, retained error causes, redaction and bounded separate failure events. End-to-end service failure qualification remains pending.
Native Debian 13 qualification of the exact test binary ran as UID 1000 with no-new-privileges and isolated networking: process elapsed 0.028980 s, CPU 0.016426 s, cgroup memory peak 3,424,256 bytes. These are pure/fake-fixture diagnostic tests, not a real namespace failure, a cause determination or a service-wide resource measurement.

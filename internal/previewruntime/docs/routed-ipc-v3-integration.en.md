# Routed IPC v3 integration fixture — RED

`TestRoutedIPCV3SharedStoreLifecycle` exercises the real shared configuration store,
R2 reserve files, G1, selected reader, RoutedStoreSourceV3, authenticated Unix peer
wrapper, RoutedSessionV3, RoutedRemoteAuthority and Group. Only kernel/network I/O
uses existing typed fixtures. The test runs as a non-root Linux account; helper
UID 2000 is logical scope distinct from the actual store-owner UID, not evidence
of three-process UID isolation or native packet forwarding.

At this freeze the test is intentionally RED. Boot4 preserves both imported rules
without configuring L3. Stage4/Validate4/Commit4/Confirm4/Save4 pass. After Stage6,
Validate6 fails with ANDEIVA_ADMIN_HELPER_UNAVAILABLE. A non-race WSL/Go1.27.4 run
measured helper PrepareView at 43 ms, 581 ms, 920 ms, then 3.000320499 s with a
selected-state read error; Resolve arm/apply/confirm measured 1.027/1.167/1.494 s.
The helper session closes with ANDEIVA_PREVIEW_UNAVAILABLE. Total run: 10.447 s.
No timeout, validator or protocol change is included. The later confirmed helper
restart and inverse assertions are present but not reached; expiry coverage and
complete acceptance remain pending the reader-owner fix. No native Boot4 claim.

Run from the repository with Go1.27.4, a prepared offline module cache, and a
non-root Linux account (root explicitly skips this filesystem profile):

```sh
GOPROXY=off GOSUMDB=off go test ./internal/previewruntime -run '^TestRoutedIPCV3SharedStoreLifecycle$' -count=1 -timeout=10m -v
```

The fixture alone converts temporary test directories to 02750 and records to
0640 after all private writers close; checkpoint.lock stays 0600. Production
permissions are unchanged. The Unix handshake completes before the shared writer
opens, including reconnect. No fixture files, hashes or paths establish authority.

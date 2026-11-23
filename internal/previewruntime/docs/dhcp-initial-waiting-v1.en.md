# Initial WAN acquisition waiting, version 1

Change note: the experimental routed DHCP controller now distinguishes initial acquisition waiting from recovery-required failure. A waiting response carries no lease and makes no network or configuration change. It preserves an already completed integrity qualification; it never creates readiness or permits traffic.

The producer reads acquisition phase and lease atomically. Waiting requires a confirmed live acquisition that has never granted a lease or received a revocation. The helper checks released selected work and closed forwarding before returning the versioned response, before gate or lease-manager effects. Unknown versions, malformed replies, cancellation, EOF, owner death, expiry and any uncertainty after effects retain failure behavior. No public request may manufacture this state. Older peers reject the new response rather than treating it as a grant.

Validation uses real private pipes and the real control codec, with explicit acquisition/kernel/store doubles. These tests do not prove native DHCP integration. Native acquisition through the complete controller and resource benchmarks remain pending. This change adds no process, timer or persistent file; begin adds one fresh owner probe, within the unchanged operation deadline.

Reproduce with Go 1.27.4 on Linux/WSL:

```sh
go test -race ./internal/dhcpclient ./internal/firewallipc ./internal/previewruntime -run 'TestInitialAcquisition|TestRoutedDHCP|TestRoutedIntegrity|TestConservativeLease|TestReconfigure' -count=1 -timeout=120s
go vet ./internal/dhcpclient ./internal/firewallipc ./internal/previewruntime
go test -c -o /tmp/andeiva-dhcp-waiting-v1.test ./internal/previewruntime
```

Reverting the change restores the previous recovery-required behavior; it does not restore leases or extend deadlines. No installation or activation procedure is introduced.

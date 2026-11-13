# Private selected-source reader

Root launches one fixed, capless reader as the helper identity with the shared
reader group. Four pinned readonly directories and two private pipes are its
only bootstrap resources. Parent PID/start, child PID/start and a fresh nonce
bind the bounded response; failed reads publish no successful result.

Retirement reads CURRENT with full history through ObserveRetirementSourceV3.
DHCP reads an exact selected work and canonical DHCP bundle, then revalidates
the selected reference. Neither mode grants authority by itself. Root must keep
the existing publication barrier until its effect finishes. No API-supplied
path, identity, executable or cached lease is accepted.

Unit tests cover the process/codec boundary and real selected storage with
simulated physical I/O. A separate Debian 13 native test launches the actual
capless child after grouped bootstrap, readback and retained-helper API restart.
After the writer exits, root holds its original checkpoint lock; current selection
is accepted and a foreign old scope is rejected. This does not establish namespace
retirement, DHCP readiness or the live DHCP publication barrier.

Use the prerequisites and private-mount/cgroup containment in
[native launch qualification](routed-launch-native-v3.en.md), selecting mode
`--isolated-selected-preflight-lab` in `packaging/preview/tests/routed-launch-native.sh`.
Require `TestNativeRoutedSelectedPreflightV4` PASS and
`ANDEIVA_NATIVE_LAUNCH_CLEANUP_OK`; skipped tests are not native evidence. Compare
host addresses, routes, rules and forwarding before and after. One native run took
1.76 seconds; the entire harness used 1.883 CPU seconds and peaked at 36.7 MiB.
These are test measurements, not permanent-service budgets.

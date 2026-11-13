# Native grouped launch fixture V3

Status: integration blocked before API readiness. This fixture is not production deployment or traffic qualification.

`TestNativeRoutedLaunchV3` uses the production launcher and both V3 factories. A separate capless API-identity process prepares a fresh declared store and real reserve pools offline. It closes writers before converting the reader profile. The helper reads those profiles, constructs the physical kernel/network adapters, observes actual listener absence and requires all three managed tables to be absent before boot. No simulated engine provides readback. The otherwise mandatory local-engine slot rejects every action; its action-call count must stay zero.

The planned positive assertions are exact API/helper UID, primary/supplementary groups, all five capability sets, no-new-privileges, distinct namespaces, read-only helper pool descriptors, denied helper access to credentials and the writer lock, actual V3 peer authentication, grouped boot/readback, certificate-verified HTTPS anonymous rejection/authenticated read, and API restart retaining the helper PID. Two isolated veth pairs connect the gateway to disposable peers; both ends are up without IPv4 addresses or routes. No host link is changed; IPv6 traffic is not qualified. The fixture does not qualify forwarded traffic, pending-operation process death, OS-incarnation recovery or descendant cleanup under an interrupted kernel command.

Build on Linux with the repository Go toolchain:

```sh
go test -c -o previewruntime.test ./internal/previewruntime
go vet ./internal/previewruntime
bash -n packaging/preview/tests/routed-launch-native.sh
```

Transfer the binary and script through the approved pinned laboratory connection. Verify hashes before installing them in a new root-owned directory with mode 0755; use 0755 for the binary and 0700 for the script. Run only on the authorized Debian 13 client, inside a root systemd unit with `PrivateMounts=yes`, `TemporaryFileSystem=/run/netns:mode=0755`, `ProtectSystem=strict`, `ReadWritePaths` limited to that fixture directory, `KillMode=control-group`, `LimitNOFILE=256`, `TimeoutStopSec=5s` and `RuntimeMaxSec=110s`. The command inside that unit is:

```sh
bash /APPROVED_FIXTURE/run.sh --isolated-lab /APPROVED_FIXTURE/fixture.test
```

The harness generates unique namespace names and checks their inodes before cleanup. It refuses namespace removal while processes remain. The containing unit remains responsible for descendant cleanup. Preserve a failed binary and its logs; use a separate unit and directory for the next attempt.

Observed attempt, 2026-11-12: binary SHA-256 `501a99e6d02b071b370108cad6947b7e29ba4ac7652516fe8bec1664eba4232f`, script SHA-256 `6c4e4707229c9c636c38ba55f4b2feb2f6e9f453d396f8fc72d787a78f95bbfc`. The helper reported UID 62002, GID 62003, supplementary group 62004, only NET_ADMIN in all five sets, NNP=1 and 57 read-only pool descriptors. The API did not reach readiness: `ANDEIVA_OPERATION_UNAVAILABLE`. Unit result was exit-code 1; elapsed 427 ms, CPU 290395000 ns, peak memory 30687232 bytes. These measure a failed startup, not a runtime resource budget. Host rules, routes and forwarding comparisons passed; no named host namespaces remained, as reported by the orchestrator executing the remote unit.

The diagnostic build adds fixed stage names without credentials or configuration bodies. Compile, vet and shell syntax checks passed. Complete native success and final-source review remain pending. No Docker or EKS deployment is added.

## Native qualification after corrections

A subsequent Debian 13 run passed the complete fixture in 1.86 s: distinct real API/helper identities, API capability removal, helper CAP_NET_ADMIN only, cross-role read rejection, grouped physical boot/readback, certificate-verified HTTPS (anonymous 401/authenticated 200), and API restart retaining the helper. Namespace cleanup passed; host routes, nft rules and IPv4 forwarding remained byte-identical. The complete qualification unit used 1.907755 s CPU and peaked at 40,755,200 bytes, including fixture setup and all processes. This is not idle RSS or a production sizing result. The binary SHA-256 was ac41c85bff907010f05859085eb5d242047c72ff55c3340189e20999ad9e6a43; the harness SHA-256 was 3e6188272e2d6663f287b08373e6aa655c31be8a15af2ed63b98c46d5b1c6f5b.

The earlier failure exposed owner reads incorrectly requiring the helper group; owner and helper reads now use separate identity gates. Unsupported dummy/down links were replaced by isolated active veth peers, without relaxing observation validation. These results do not qualify forwarded traffic, runtime deadlines under load, host-interface activation, installation or OS-reboot recovery.

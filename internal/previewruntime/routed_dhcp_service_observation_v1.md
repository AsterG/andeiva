# DHCP acquisition resource observation, version 1

Development component under ADR-062. It observes an acquisition service; it does not authorize forwarding, replace selected lease/R2 recovery, prove current socket possession, or qualify an installed appliance.

The private root/helper `prepare` response now requires service-cgroup version 1, kernel device/inode identity and four SCM_RIGHTS descriptors: request pipe, response pipe, producer pidfd and read-only cgroup pin. `activate` and `stop` must contain neither descriptors nor preparation metadata. Old, missing, unknown and extra capabilities fail closed. Public API, CLI and web contracts are unchanged.

The helper verifies the root-authenticated binding, cgroupfs/access/ownership/identity, exact incarnation path, producer pidfd/start and current cgroup. It retains independent cgroup and producer pins. The acquisition view is installed before activation; standby still requires empty inventories and never consumes a preactivation `Current` response. A typed activation call holds the listener lock until root acknowledges its own selected preflight and actual acquisition process. Observations then call the authenticated reader directly, without reentering the runtime or authority mutex.

Every observation reads all four TCP/UDP tables and bounded UDP/packet diagnostic inventories in the pinned gateway namespace. It makes two sequential captures and rechecks producer identity and the original lease/phase before and after. These are not an atomic kernel snapshot. Each capture must independently satisfy the profile; a socket may appear or disappear, but a retained inode cannot silently change cookie or attributes. No cache substitutes for a live reader response, and no deadline is extended.

Only one IPv4 UDP socket is permitted: UID 0, port 68, the exact current leased address, matching table inode and kernel creation-cgroup identity. Both physical readbacks must associate that exact address only with the selected WAN name/MAC. A diagnostic ifindex of zero is **not** bind-to-device evidence. Wildcards, foreign cgroups, wrong addresses, extra UDP, TCP listeners and IPv6 listeners are rejected.

The supported maintained-engine packet profile is RAW/ETH_P_ALL, UID 0, flags 3 and the exact nonzero WAN ifindex. Source review and isolated acquisition/renewal measurement support an initial-wait range of zero to two packet sockets with no UDP; with a current lease, one to two packet sockets and zero or one qualifying UDP socket. Two is the supported profile bound, not a universal kernel maximum. Unknown profiles, LAN/unbound packet sockets, different types/protocols/flags and excess sockets are rejected. `packet_diag` does not establish cgroup ownership, current holder or installed/locked BPF filters. The maintained privileged acquisition engine and exclusive raw-socket role remain in the trusted computing base; this is no claim that IP firewall rules contain a compromised raw socket. The maintained Linux source opens RAW/ALL and binds the interface before attaching its filter. [Maintained source](https://raw.githubusercontent.com/NetworkConfiguration/dhcpcd/v10.1.0/src/if-linux.c).

Retirement first revokes the resource view. Root's stop acknowledgement attests process drainage only. The helper releases the retained pins only after the producer pidfd reports exit and two complete TCP/UDP/packet inventories are empty. Residual sockets or uncertainty retain the pins and block a clean retirement. No group, socket or process is adopted. With no DHCP service, the adapter requires strict absence of all supported listener and packet resources.

No new persistent worker, timer, database writer, service installation, dependency or capability is introduced. Installed-unit privileges, real UID drop, integrated DHCP acquisition/renewal/retirement, independent review and CPU/RAM benchmarks remain separate gates. Container/Helm infrastructure is unchanged; this internal Linux appliance adapter requires the existing dedicated namespace/cgroup assembly.

## Validation

```sh
go test -race ./internal/localobserve ./internal/previewruntime -run 'TestParseSocketTables|TestRoutedDHCP(Service|JobsV4|Deferred|Owner)|TestRoutedEmptyListeners' -count=1
go vet ./internal/localobserve ./internal/previewruntime
go build ./internal/localobserve ./internal/previewruntime
GOOS=windows GOARCH=amd64 go build ./internal/localobserve ./internal/previewruntime
```

Tests distinguish pure inventory/I/O models and real unprivileged SCM_RIGHTS transfers from privileged acquisition. They do not claim a native adapter pass. Existing reader tests cover EOF, replay, cancellation, owner death and original expiry. Private native diagnostics require their separate build tag and remain outside normal packages.

## Source change

Added strict acquisition resource observation and physical-absence retirement; extended only the private prepare capability bundle. Shared release tracking remains with the orchestrator.

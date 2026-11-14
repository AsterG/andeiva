# DHCP acquisition Local-In control

Development implementation under ADR-063; integrated renewal qualification is pending.

The routed engine derives one control rule from the exact canonical selected network when its WAN uses DHCP: IPv4 packets arriving on that WAN, UDP source port 67 and destination port 68. It is part of the owned `andeiva_local` INPUT table and its complete readback. Static WAN and absent routed network have no acquisition rule. The input chain retains its drop policy; other interfaces, address families, protocols and ports receive no permission from this rule.

Acquisition may recover without an existing lease. This rule therefore has no connection-tracking, address or lease-expiry predicate. The maintained client validates DHCP transactions; a DHCP router is not presumed to be the DHCP server. The rule grants neither administrative access nor forwarding. Selected lease/R2 identity, epoch, original deadline and forwarding recovery are unchanged. Existing service provenance, socket inventory and process-drain checks still apply.

Compilation accepts a canonical network revision through internal trusted assembly, never a caller-supplied interface or arbitrary nft fragment. Readback recompiles that revision and rejects missing, changed or extra resources. Changing the selected network recompiles the local table even if the local policy revision is unchanged, so rollback removes stale acquisition admission. Service retirement must still drain the acquisition process and prove resource absence; this compiler does not perform process lifecycle operations.

Validation: `go test -race ./internal/localnft ./internal/routedactivation`; `go vet ./internal/localnft ./internal/routedactivation`; `go build ./internal/previewruntime`; `GOOS=windows GOARCH=amd64 go build ./internal/previewruntime`. Tests use pure compilation and the real routed engine with simulated kernel/network I/O, not a native DHCP server. The change adds one rule/counter per enabled DHCP WAN and no process, timer, set or persistent state. Native correctness and resource measurements remain pending. No Docker, Compose, EKS/Helm or installed service profile changes.

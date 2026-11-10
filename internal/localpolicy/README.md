# Local service policy POC

Pure Go contracts, validation, nftables JSON compilation, impact preview and
comparison of supplied observations for traffic addressed to ANDEIVA itself.
No host changes, listeners or privileged operations are performed.

- [Design and proposed transaction integration](ADR.md)
- [English](docs/en.md) · [Español](docs/es.md) · [Português](docs/pt.md)

Management defaults to explicitly selected LAN addresses and explicit source
prefixes. Multiple LAN/WAN/other bindings are representable; each WAN binding
requires opt-in. This does not implement a runtime interface selector or activate
any service. Forwarding policies remain separate.

This package is not connected to the existing preview API, CLI, Web, transaction journal
or service supervisor. Do not apply its default-drop batch on the appliance host.

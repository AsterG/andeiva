# Routed inventory without local services

ADR-056 permits a narrow internal projection for a routed candidate. This code
derives local interface metadata from the canonical candidate network: exact
LAN and WAN addresses for the supported static profile, or only the static LAN
for WAN DHCP. It does not fabricate a DHCP address, define services, grant
management access, create forwarding/NAT policy, or modify host SSH/HTTPS.

Only a local configuration with **zero service definitions**, including disabled
definitions, can gain the inventory exception. Its previous inventory must be
empty or exactly match the prior routed network. A schema-4 no-network source
can authorize this change only with empty inventory. Existing local policies
with service definitions retain their exact revision and receive no exception.
An API `local_services_config` differing from Running remains rejected, even
when it happens to equal the derived result.

Stage and owned Replace derive the local candidate under the existing coordinator
lock and candidate ownership/generation checks. They leave Running and Startup
unchanged. Commit retains the complete previous snapshot for compensation.
Historical Rollback loads its authenticated, verified bundle and preserves its
original local revision; it never reconstructs historical content. The ordinary
confirmation deadline, selected-work checks, audit and recovery paths remain.

`RoutedNoServicesTransitionV3` is a pure predicate over canonical revision
payloads and hashes. It grants no authority. Boot/restart consumers must still
authenticate the original saved/target bundles and retain independent network,
table and listener readback. The existing grouped engine checks actual owned
table state and listener observations before effects; the native adapter scopes
those observations to its retained gateway namespace.

Validation uses the real coordinator/store and grouped engine with modeled I/O.
It covers services (enabled and disabled), foreign inventory, tampered hashes,
ordering, API metadata rejection, candidate replacement/concurrency, unchanged
Startup, retained rollback, and refusals on foreign listeners/tables. Run:

```sh
go test -race ./internal/configpoc ./internal/routedactivation -run '^TestNoServicesV3' -count=1
go vet ./internal/configpoc ./internal/routedactivation
```

Debian activation/restart/rollback and resource measurements remain separate
native gates. These unit tests do not prove kernel behavior. No new engine,
service, listener, timer, persistent schema or external dependency is added.

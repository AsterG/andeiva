# Prepared operations runtime

The trusted `OpenOperationsRuntimeV2` factory connects to the authenticated v2
helper socket, constructs the absolute-deadline adapter and opens the selected
configuration store with its existing reservation pools. It does not open a v1
writer, prepare pools, migrate configuration or enable a runtime flag. Cold boot
still requires the coordinator's verified reservation/bootstrap contract.

`adminapi.NewOperationsV2` uses the same session authority as the service. Existing
TLS, origin, CSRF and role checks remain mandatory. New v1 configuration writes
return `ANDEIVA_V2_OPERATIONS_REQUIRED`; v2 operations use the existing namespace,
admission, execution and query contracts. `GET /api/v2/config/current` reads the
actual selected global and firewall projections together under the store lock.

`GET /api/v2/network/interfaces` requires a trusted inventory provider for the
helper's target namespace. No provider means unavailable, never discovery on the
API host. The bounded response includes names, MAC addresses, MTU, link state,
kind and IP/prefix pairs; it excludes indices and internal platform details.

Closing the API service closes its catalogue and helper connection. It does not
delete rules or namespaces. A pending helper lease retains its independent
deadline and restoration behavior. A confirmed policy remains selected in the
helper. Tests cover real store/Unix transport with simulated engines; they do not
qualify host networking, permanent installation or grouped routed cold boot.

Run the `TestRuntimeServiceV2`, `TestRuntimeOperations`, `TestRuntimeNetworkInventory`
and `TestRuntimeV2` tests with `go test -race` on Linux. Also run `go vet` for
configpoc, adminapi and previewruntime, and `go build ./...`.

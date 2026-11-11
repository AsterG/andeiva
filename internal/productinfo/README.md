# Public product identity

Authenticated GET /api/v1/system/info returns only ANDEIVA product identity.
Admin and viewer sessions use the existing TLS, host, origin and session checks.
It is a read-only contract and does not execute a configuration transaction.

Fields: product, optional version, channel and update_status. Packaged preview
versions use the validated 0.1.0~alphaN format and the experimental channel.
Development builds omit version. Update status is currently always unavailable;
there is no catalogue request, update installation or up-to-date assertion.
Operating-system, kernel, engine and source-build details are not returned.

The package builder sets the same identity in backend and CLI. Runtime environment
variables do not override it. The CLI system info command queries the connected
appliance with verified HTTPS; --version reports its own local build instead.
The browser consumes the authenticated server contract and does not infer a
version from its assets. Go client decoding is bounded to 4096 bytes and rejects
unknown, duplicate, case-folded or inconsistent identity fields.

Run the following, then the normal frontend and package checks:

```sh
go test -race ./internal/productinfo ./internal/adminapi ./internal/adminclient ./internal/cli
```
EN/ES/PT operator
instructions are in packaging/preview/docs and frontend/docs. These tests include
fixtures; installed service evidence is recorded separately after deployment.

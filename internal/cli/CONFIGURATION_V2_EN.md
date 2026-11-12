# Configuration operations

The `configuration` commands require an authenticated v2 administrative endpoint.
The selected store determines whether firewall-only or grouped routed operations
are available. Installing a CLI does not migrate or activate a configuration.

Use a trusted CA and an individually provisioned, owner-only credentials file:

```sh
andeiva configuration status --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
cat stage.json | andeiva configuration stage --request-file - --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration validate --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration commit --confirm-seconds 60 --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
```

`stage.json` uses the typed `OperationRequestV2` contract: operation `stage` and
the full schema 6 configuration. The CLI derives the nested network revision
from its validated data. Admission uses the selected global generation as an
exact decimal string, preserving all uint64 digits. Stage and Validate do not
activate forwarding. Commit is confirmed-only, with a 30–120 second deadline.

Before execution, stderr prints `ANDEIVA_OPERATION_ACCEPTED` and the durable ID.
If execution is interrupted, query that ID rather than submit a replacement:

```sh
andeiva configuration operation --operation-id OPERATION --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
```

An accepted operation can be explicitly resumed with `execute --operation-id`.
The command does not automatically retry execution or fall back to v1 writes.
It logs out after success or failure and closes newly created namespaces after
terminal results. Exit 3 means execution remains accepted; inspect its ID.

Confirm uses the originating Commit ID and the composite target from status.
Save persists all of Running. Rollback also requires confirmation:

```sh
andeiva configuration confirm --origin COMMIT_OPERATION --target COMPOSITE_REVISION --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration save --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration rollback --target SAVED_COMPOSITE_REVISION --confirm-seconds 60 --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
```

Runtime activation, kernel enforcement, imported-state compatibility and recovery
require their own qualification. Transport tests and browser fixtures alone do
not prove them. Do not change an appliance's management links using an unqualified
runtime. API/Web/CLI use the same admission and execution contracts.

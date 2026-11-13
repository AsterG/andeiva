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
the full schema 4 or 6 configuration, according to the runtime capability. Schema4
is policy-only and never acquires an invented network plan. For schema6, the CLI
derives the nested network revision from its validated data. Admission uses the selected global generation as an
exact decimal string, preserving all uint64 digits. Stage and Validate do not
activate forwarding. Commit is confirmed-only, with a 30–120 second deadline.

Stage refuses an existing Candidate. To replace or discard your grouped Candidate,
copy its exact `stage_operation_id` from status and choose an explicit operation:

```sh
cat replacement.json | andeiva configuration replace-candidate --expected-candidate-stage STAGE_OPERATION --request-file - --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
andeiva configuration discard-candidate --expected-candidate-stage STAGE_OPERATION --url https://HOST:9443 --ca-file ca.crt --credentials-file credentials.json
```

`replacement.json` contains `operation: "replace_candidate"` and the complete
`config`. The CLI passes `expected_candidate_stage_operation_id` unchanged, using
the selected global generation for CAS. Replacement preserves the local Candidate;
it cannot bypass its access-recovery proof. Neither operation changes Running,
Startup or traffic. A stale Candidate remains readable; replacement never happens
automatically. After replacement, validate before applying. Ambiguous abbreviated
commands, including `r`, are rejected; `rep`, `rol` and `dis` are distinct prefixes.

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

Read protected history with `andeiva configuration audit --limit 50` and the same connection flags. `--before SEQUENCE` is an exclusive cursor. Filtering and scan bounds do not imply complete history; `truncated` explicitly reports an incomplete scan. This read does not admit or execute configuration operations.

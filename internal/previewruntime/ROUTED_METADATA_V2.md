# Routed runtime metadata profiles

`Metadata.Validate()` and the legacy `ReadMetadata()` remain schema-1-only. Schema 1 describes the laboratory host, gateway, source and sink: all four namespace identities must be nonzero and distinct. Its JSON representation is unchanged.

Routed assembly calls `Metadata.ValidateRouted()`. It accepts the existing schema 1 validator or the explicitly selected `RoutedMetadataSchemaVersion` (2):

| Field | Schema 2 requirement |
| --- | --- |
| `run_id` | Canonical 32-character lowercase hexadecimal identity |
| `boot_id` | Canonical lowercase UUID, excluding the null UUID |
| `host_namespace`, `gateway_namespace` | Nonzero, distinct namespace identities |
| `source_namespace`, `sink_namespace` | Both zero; no fixture namespaces are fabricated |

Unknown versions and mixed profiles are rejected. Missing source/sink identities in schema 1 never promote it to schema 2. Legacy roles reject schema 2. The deployment loader must explicitly select the profile and independently pin its actual host and gateway descriptors; there is no automatic conversion.

Structural validation grants no authority. Existing descriptor, process, boot, channel-peer, selected-work and guardian checks still apply. A request cannot replace supervisor metadata. No capabilities, deadlines, configuration schemas or host networking are changed by this extension.

Verification with the repository Go 1.27.4 toolchain:

```sh
go test -race ./internal/previewruntime -run '^(TestRoutedMetadata|TestRoutedHelperV3|TestRoutedAPIV3|TestRoutedLaunchV3|TestRoutedKernelV3)' -count=1 -timeout=3m
go test ./internal/previewruntime -run '^$' -bench '^BenchmarkRoutedMetadataV2Validation$' -benchtime=10000x
go vet ./internal/previewruntime
go build ./...
```

Tests cover legacy JSON compatibility, explicit profile selection, strict decoding, identity substitutions and refusal of an unbound kernel/helper context. The benchmark measures only pure validation, not appliance sizing. This slice does not qualify two-namespace deployment, traffic, host handover or recovery on actual hardware; those remain integration gates. Rollback retains the schema-1 assembly rather than coercing schema-2 metadata into a legacy role.

A Linux development sample of 10,000 pure validations measured 434.7 ns/op, 16 B/op and one allocation/op. No files, descriptors, processes or retained caches are added by this validator; the existing hexadecimal parser accounts for the allocation. These measurements do not qualify appliance performance.

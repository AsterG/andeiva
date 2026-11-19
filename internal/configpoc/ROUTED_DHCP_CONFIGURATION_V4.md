# Active DHCP configuration contract v4

The selector and writer share the transition checks for ADR-074. The
active-DHCP admission guard remains in force. Runtime production, helper
activation and the public API depend on the remaining phases.

The optional required-feature marker is
`configuration.routed-dhcp-configuration.v4`. It is sticky once selected and
requires the existing routed, shared-reader, DHCP v3 and R2 profiles. Older
readers must refuse the marker even after its optional payload is absent.
Unmarked records retain the existing v3 validation rules.

## Preserving the original source

The original DHCP Work, acquisition identity, lease evidence, epoch, original
Running revision and physical R2 scope do not change. The original generation
is never rewritten to match a later configuration generation. This contract
binds configuration lineage; it supplies no new grant or forwarding authority.

An impact of `preserve` requires equality of the **complete canonical network
revision** in the original Work, Before, and Target. Any network change,
including LAN or DNS configuration, is `replace`. Replacement is classified but
refused with `ErrRecovery` until the single shared acquisition/retirement
contract for ADR-072/074 is implemented. This phase does not define a second
acquisition identity or launcher.

The selected header has at most two immutable references:

* `transition`: the operation-specific projection selected before Intent or
  effects. It binds lineage, actor, namespace, operation ID, fingerprint,
  expected/target generation, exact Before/Target, original DHCP Work and an
  existing SourceSelection. Grouped operations also bind their existing Work.
* `continuation`: the final receipt, binding the Transition, immutable final
  operation, and actual final configuration including audit and verified index.

A Transition never references its future final receipt or final operation.
This avoids a SourceSelection/operation/configuration cycle. A previous final
Continuation stays selected while the next Transition is pending; it cannot
disappear while preserving the source. SourceSelection uses existing G1 graph
budgets and prior headers; there is no separate history log or compactor.

SourceSelection must already contain the exact accepted operation and its
physical R2 admission. A pending Transition permits only that operation's exact
Intent. Creating the Transition also checks the entire SourceSelection tuple
against the actual preceding selector edge; a self-consistent invented selector
pointing at the same state is insufficient. The final receipt retains its immutable operation independently of
later circular catalogue reuse or namespace retirement. Its accepted source,
projection, outcome, audit and final configuration remain validated.

Metadata Stage/Save have no forwarding pause. Future unchanged-network grouped
Commit may have a measured forwarding closure but must preserve the original
source and must not force a DHCP request. Runtime enablement, management LAN and
local-console continuity, Confirm/rollback and measured closure remain later
phase acceptance criteria, not claims made by this reader contract.

## Reader and resource boundaries

Canonical record decoding rejects unknown members, aliases, duplicates, null
optional alternatives and mixed union branches. A Transition or receipt is
bounded to 16 KiB. G1 visits source states, configurations, grouped Work,
operation audit and verified indexes using its existing object, byte, depth and
I/O budgets. Only one next state is materialized when comparing a changed
header; historical summaries retain two hashes. No cross-request validation
cache is introduced. R2 claims remain distinct from the source's system claim;
closing credit is not reused.

The writer applies the same edge validation when the continuation header
changes. It requires the current selector as the source and verifies the
physical reserve on the prospective state before changing the selector.
Admission, legacy v3 validation and runtime factories retain their existing
checks. Contract
tests construct future-format records with real low-level R2 pool claims;
these fixtures do not demonstrate product admission or a functioning Commit.

Qualification commands and measured reader costs must accompany the PR. Native
WAN/LAN resource and forwarding measurements are pending runtime implementation
and are not inferred from Docker unit tests. A prepared reader is not completion
of ADR-074 or of the routing milestone.

## Reproduce the focused checks

Run from the repository root in a development environment. The historical
sources are `22adc79893c5036bf5d42b60334ae74400a3d6bb` and
`070c52627642a95404cda6251470ab9940da5418`. Build their test executables using
their unmodified product code and locked modules; copy
`routed_dhcp_configuration_v4_prior_linux_test.go` into each historical tree as
`internal/configpoc/routed_dhcp_configuration_prior_adapter_linux_test.go` before
`go test -c ./internal/configpoc`. The adapter calls each original shared-store
reader. It changes no product implementation or dependency version.

Place the executables at `.tmp/prior-readers/shared-reader-22adc.test` and
`.tmp/prior-readers/shared-reader-070c.test`. With the prepared offline development
image and its locked module cache:

```sh
docker run --rm --network none --cap-drop ALL \
  --security-opt no-new-privileges:true --memory 1536m --cpus 2 \
  --mount type=bind,source="$(pwd)",target=/src,readonly \
  --mount type=bind,source="$(pwd)/.tmp/prior-readers",target=/prior,readonly \
  -w /src andeiva-go-check-ci-fix:latest bash -c '
    set -eu
    go test -race ./internal/configpoc -run "^TestRoutedDHCPConfigurationV4" \
      -count=1 -timeout=180s -args \
      -reclaim-old-reader=/prior/shared-reader-22adc.test
    go test ./internal/configpoc \
      -run "^TestRoutedDHCPConfigurationV4OldReaderMarker$" \
      -count=1 -timeout=30s -args \
      -reclaim-old-reader=/prior/shared-reader-070c.test
    go vet ./internal/configpoc
    go build ./internal/configpoc
  '
```

The tests explicitly require a historical executable for compatibility evidence;
a default skipped compatibility test does not qualify. No command above targets
an appliance, acquires a lease or changes network interfaces.

Translations: [Español](ROUTED_DHCP_CONFIGURATION_V4_ES.md),
[Português](ROUTED_DHCP_CONFIGURATION_V4_PT.md).

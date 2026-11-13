# Compensated plans and recovery-reserve retirement

A confirmed commit can fail before its confirmation is published. After verified compensation, the final operation is `failed_rolled_back` without a confirmation outcome. Its physical plan still contains the original lease and deadline. Those fields must not be removed to recycle its reserve.

The prepared v2 coordinator records `operation_compensated` resolution version 2. It binds the original operation, exact physical plan binding, lease, deadline, previous and target snapshots, and protected completion audit. The same contextual validator checks the operation, subject, domain, generation, snapshots and audit. It creates neither a confirmation child nor a recovery actor. Existing version 1 confirmation and timeout resolutions retain their encoding.

The sticky `reserve_compensation.v1` required feature is selected with the compensated final operation, before its archive can be published. The archive and resolution use explicit version discriminators. The feature remains after all physical slots are retired and across checkpoints. Older readers reject the store before a coordinator can apply effects. The metadata admission envelope reserves these feature bytes in advance; logical quotas, closing allowances and physical pool capacities are unchanged.

Retirement still requires the archive in both exact selected states and the original pool compare-and-swap checks. Partial retirement resumes with the same proof. An unconfirmed prospective target remains retained evidence: the graph inspector accepts it only as a non-live snapshot whose complete canonical hash equals the original plan target, with the feature and verified compensation facts. The same snapshot is never accepted as live Running. Audit and snapshot dependencies remain visible to full graph inspection.

## Scope and recovery limits

- The implementation addresses compensated Commit/Rollback plans with an unpublished confirmation lease. It does not add a general system/boot resolution or manufacture a confirmation for immediate operations.
- Existing incomplete version 1 archives are rejected and preserved. Some may already have retired a slot using the old proof digest; automatic rewriting or replacement is not supported. A separate reviewed repair or restoration procedure is required. Do not remove the feature, edit objects, change leases or delete protected audit to downgrade.
- New stores and voluntary migrations must retain verified backups. An older binary can read an unchanged legacy fixture, but cannot reopen a store after the feature is selected.
- This library change does not activate an appliance runtime, prove kernel recovery, authorize protected deletion, or close storage-exhaustion resilience requirements. Native appliance and full release qualification remain separate.

## Verification

Use the repository Go 1.27.4 toolchain and provisioned dependency cache:

```sh
go test -race ./internal/configpoc -run '^(TestReserveCompensat|TestReserveCoordinator|TestReserveProfile|TestReserveFuture|TestReserveEnvelope)' -count=1 -timeout=5m
go vet ./internal/configpoc
go build ./...
```

`TestReserveCompensationActualPriorReaderRefusal` additionally requires `-args -reclaim-old-reader=/absolute/path/to/prior-configpoc.test`, compiled from the preceding source with `TestReclaimPriorReader`. Skipping it is not compatibility evidence. The tested predecessor is `7fe62a0634ed3de00a652dff95aff31f306ec1ff`.

Tests use real temporary files and pools with simulated engines. They cover interrupted intent, selected finality before archive creation, partial slot retirement, abrupt process exit, immutable replay, missing and foreign references, one-nanosecond deadline differences, live/prospective separation, graph closure, sticky features and refusal by the actual preceding reader. They do not simulate power loss.

A source-only sample serialized the additional resolution in 839–840 bytes and measured approximately 1.12 ms and 1,618 allocations per contextual validation on the development filesystem. The feature changes an existing state publication; the resolution adds one immutable object. These observations are not appliance RAM sizing or a throughput guarantee. The test reports current measurements for reproduction.

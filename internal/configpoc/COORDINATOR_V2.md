# Internal configuration v2 coordinator

This coordinator is an inactive integration foundation over the same selected v2
store. It is not wired into the appliance, administrative transports or privileged
helpers. It does not migrate an installation automatically or advertise v2.

It keeps canonical firewall/schema 4 and local-service/schema 3 revisions intact
inside a schema 5 composite reference document. Domain projection counters are
persisted independently of the global generation. Candidate, Running, Startup
and LastGood remain separate; Save is explicit.

An authenticated trusted subject and admin role are required. Admission persists
the exact request and reservation without effects. Execution selects pending and
intent before touching engines. Every component is read back before authoritative
state, immutable outcome and audit are selected together. Uncertain effects or
persistence fence new mutations instead of publishing unverified Running.

Commit Confirmed links the originating operation to an independent timeout and
recovery record. Session/namespace expiry does not cancel recovery or free its
reserve. Restart reconciles durable intent and pending confirmation. A rollback
target needs a verified revision witness, not merely an existing Candidate object.
Local Services mutations are denied before engine effects until the separate
listener/evidence mapping is implemented and reviewed.

## Reproduce without privileges

With Go 1.27.4 and the existing dependencies available:

```bash
go test -race ./internal/configpoc -run 'TestCoordinatorV2|TestV2' -timeout 15m
go vet ./internal/configpoc
go build ./internal/configpoc
ANDEIVA_CONFIG_V2_ENGINE_ENDURANCE=1 go test -race ./internal/configpoc \
  -run '^TestCoordinatorV2EngineEndurance5000$' -count=1 -timeout 45m -v
```

The optional endurance fixture executes 5,000 six-operation cycles and cold
reopens at each thousand cycles. It reports actual process RSS, heap, CPU,
elapsed time and logical/allocated disk/inodes. Its 20,000 Apply calls use
simulated engines. Process-exit fixtures model durable component state with
files; neither test proves real kernel enforcement or power-loss tolerance.
The test needs several GiB and hundreds of thousands of inodes. Use an isolated
test directory/filesystem with sufficient capacity, never a live appliance store.

Remaining gates: real-engine integration, durable authentication adapters,
Web/CLI/API parity, opt-in cutover/downgrade protection, Local Services evidence,
protected audit lifecycle and physical capacity/continuity qualification.
No protected history is deleted. Thirty-day retention is a qualification target,
not an infinite-storage or physical reservation guarantee.

[Español](COORDINATOR_V2_ES.md) · [Português](COORDINATOR_V2_PT.md)

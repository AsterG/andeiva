# DHCP action-authority reads

The helper uses the same selected action-authority reader as ordinary routed operations when the full-integrity gate is configured. DHCP still validates current work, selected identity, physical reserve bindings, terminal archive finality, dependencies and the final selector. Cold start, full inspection, fresh/reboot scope and isolated job preflight retain the full-history reader. With no integrity root the reader remains full-history; this change grants no missing integrity authorization.

All four authority checks and original RPC deadlines remain. No cross-request cache is introduced. Tests exercise prepared/applied/withdrawn/released states with both reader policies, foreign work/identity, substituted reserve and missing terminal FinalWork. Existing runtime closure and generic dependency/selector negatives remain required.

Run: `go test -race ./internal/configpoc -run 'TestRoutedDHCPSelectedV3(IndependentFullReaderAndRetirement|ActionReaderAndRetirement)'` and `go test -race ./internal/previewruntime -run 'TestRoutedDHCPRuntimeV3'`. Native renewal and API-restart timing require a separate Debian laboratory run; unit timings are not appliance throughput guarantees.

# Routed recovery across an OS boot

A trusted change of OS boot identity is distinct from a controller/helper restart.
The coordinator never sends an old namespace plan to a new incarnation or extends
the old confirmation deadline. Startup remains the boot source; Candidate is kept
with its original base and owner.

For an unresolved routed confirmation or boot attempt, a private typed boundary
retains the original configuration, work, operation/recovery record and reserve.
The fresh boot observes its actual empty namespace, selects a new boot intent and
uses that boot record's original ten-second deadline. Old Pending remains visible
internally until fresh Startup is verified; historical Running is not relabeled
as confirmed. No API is made ready during this transition.

Only verified fresh boot finality permits supersession bookkeeping. The original
operation outcome stays immutable. Audit says `superseded_by_boot`, not that the
old target was restored. Both selected archive anchors and physical retirement
remain required before releasing the retained reserve. A sticky required feature
prevents an older reader from silently interpreting these facts.

Tests use real canonical storage, reserve files and fault/restart boundaries with
a simulated group authority. They do not prove packet forwarding, power-loss
durability or physical boot behavior. Same-boot, foreign role/run, substituted
proofs and expired boot deadlines are refused. A second OS reboot while a boundary
is unresolved is fenced before another claim; the two system slots are not
expanded or silently reused. The existing canonical boot headroom requirement
still applies. Fully exhausted-storage boot qualification and native resource
measurements remain separate gates.

Linux reproduction: `go test -race ./internal/configpoc -run
'TestRoutedOSBootBoundary|TestReserveEnvelopeMaximumDescriptors' -count=1`.

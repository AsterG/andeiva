# DHCP scheduler admission

Development component; integrated native qualification is pending.

The selected DHCP scheduler skips a tick when inspection or another operation
holds the controller lane. It creates the existing three-second reconciliation
context only after acquiring that lane and checking cancellation. Skipping sends
no request and leaves the channel intact. Cancellation releases the lane.

The public reconciliation method retains its caller context and blocking lock
semantics. The aggregate three-second limit and individual RPC limits remain;
two two-second RPCs still exceed the aggregate deadline and fence the channel.
Lease, confirmation, watchdog and recovery rules are unchanged. This does not
implement phase budgets, cancelable store I/O or a general timeout recovery.

No worker, timer, queue or persistent state is added. Avoided lock waits are not
a measured CPU/RAM improvement; native resource and acquisition evidence remains
pending. Rollback is a source revert, without changing selected configuration.

Run with Go 1.27.4 on Linux/WSL:

```sh
go test -race ./internal/previewruntime -run TestRoutedDHCPSchedulerV4 -count=1 -timeout=60s
go vet ./internal/previewruntime
go build ./internal/previewruntime
```

Tests use a real private protocol connection and a simulated grant, not a native
DHCP owner or kernel. They cover contention, cancellation at admission, channel
preservation on skipped ticks, and unchanged single/aggregate deadline fencing.
The two contention regressions use bounded real time because mutex waits do not
advance the virtual clock in `testing/synctest`; deadline cases use virtual time.

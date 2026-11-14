# DHCP scheduler admission

Development component; integrated native qualification is pending.

The selected DHCP scheduler skips a tick when inspection or another operation
holds the controller lane. It creates one 30-second reconciliation-attempt
context only after acquiring that lane and checking cancellation. Skipping sends
no request and leaves the channel intact. Cancellation releases the lane.

The public reconciliation method retains its caller context and blocking lock
semantics. Every RPC retains its three-second limit. Two sequential two-second
RPCs can complete within the scheduled attempt; a manual caller with a
three-second deadline still fences that sequence. The attempt context is never
reset between phases. A shorter caller deadline or cancellation still wins.
Lease, confirmation, watchdog and recovery rules are unchanged. This does not
implement phase budgets, cancelable store I/O or a general timeout recovery.
The 30-second ceiling is cooperative: blocking I/O or locks can delay return and
shutdown. Timeout is not proof of completed rollback; recovery references remain.

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
preservation on skipped ticks, sequential RPC budgets, manual/shorter caller
deadline fencing, and scheduler cancellation/drain. Lease-expiry gate negatives
remain separate tests in `internal/networkexecutor`; these scheduler tests do
not qualify durable publication at the full 30-second boundary.
The two contention regressions use bounded real time because mutex waits do not
advance the virtual clock in `testing/synctest`; deadline cases use virtual time.

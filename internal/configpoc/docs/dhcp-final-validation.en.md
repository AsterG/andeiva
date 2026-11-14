# DHCP selected-read final validation

The private candidate is not authority. DHCP resolution checks its Work and
identity, then revalidates all consumed dependencies, physical reserve pools,
selector and pending publication before returning a proof. Ordinary readers
retain their validation. No cache survives the call, and the caller still holds
the publication/owner barrier through effects.

The regression compares charged `IOCalls` for one final validation with the
former duplicate pass, then runs the public resolver within the single-pass
budget. These charges measure reader work, not syscall counts, CPU or disk
latency. Full-history and action readers reject changes to the selector, Work,
pending publication, pools and cancellation. Action policy additionally rejects
a new dependency read after candidate construction; Full's arbitrary uncached
additions are not covered. Existing lifecycle tests cover preparation, application
and retirement. A cleanup-budget failure must erase the public proof. No injected
FD-close error or native performance qualification is claimed.

Run on Linux/WSL with Go 1.27.4:

```sh
go test -race ./internal/configpoc -run 'TestDHCPFinalValidationV3|TestRoutedDHCPSelectedV3.*Reader' -count=1 -timeout=180s
go vet ./internal/configpoc
```

Rollback is a source revert; no stored format or selected configuration changes.

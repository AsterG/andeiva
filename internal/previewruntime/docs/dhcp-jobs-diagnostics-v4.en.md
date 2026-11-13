# Native DHCP acquisition diagnostics

Experimental laboratory instrumentation; no successful WAN qualification is claimed. The acquisition deadline remains 35 seconds. Only the supervisor owner may run the isolated native harness after independent review.

Build a separate artifact, never a packaged or deployed binary:

```sh
go test -c -tags andeiva_native_dhcp_diagnostics -o /tmp/andeiva-dhcp-jobs-diagnostics-v4.test ./internal/previewruntime
```

Record the exact source commit and artifact SHA-256. Ordinary builds retain discarded stderr and have no diagnostic file, registry, worker or timer. The native fixture also reports bounded timings of its existing reconciliation/current/live calls; it issues no extra authority RPC for those measurements.

The diagnostic artifact classifies stderr into fixed codes and records accepted hook reasons, failure stages and BOOTTIME timestamps. It does not retain raw options, addresses, hostnames or hook frames, and does not add a reader to the protocol pipe. Output is a root-only 0600 file inside a 0700 directory, exclusively created in the producer's existing private tmpfs: `/run/andeiva-dhcp/native-diagnostics/events.jsonl`. The limit is 64 KiB, followed by an explicit truncation record and discard behavior.

The fixture registers one consumer before launch. After authenticated root bootstrap, it checks the real owner handle, pidfd/start ticks, network/mount identities and cgroup, and retains the directory before activation. It collects while the producer lives and before cleanup, without rediscovering a PID after teardown. Registration, directory and pidfd pins are released explicitly. An unavailable diagnostic fails the diagnostic fixture, not silently qualifying acquisition.

Review and run both tagged/default unit tests, race, vet and compilation before the root-run native test. No timeout, privilege, packet policy or inspection relaxation is authorized by this diagnostic profile. Instrumentation resource overhead is not a production benchmark.

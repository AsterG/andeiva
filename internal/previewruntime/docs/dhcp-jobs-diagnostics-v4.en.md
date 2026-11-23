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

Duration diagnostic: accepted grant hooks include only the validated numeric `lease_seconds`; expiry hooks carry no invented duration. T1/T2 are not part of the validated event and are not inferred. The native wait trace distinguishes channel, initial waiting, conflict, storage and capacity errors, capturing a changed class within the unchanged 24-record cap. Optional controller epoch/work fields are a nonblocking post-call snapshot, not proof of the exact failing operation. No raw errors, options, addresses or hostnames are added.

Per-verb trace: the diagnostic artifact retains at most 63 fixed records in memory per process. Calls use TryLock; contention/capacity drops are declared in one additional summary. No I/O, worker, timer or extra RPC occurs while recording. Only after the fixed native API/helper role returns does TestMain flush to its private stderr, outside the recorder lock, with a total limit of 64 records/32 KiB. Prior role failure is preserved if flushing also fails. Records contain only fixed side/verb/error/context classes, elapsed time and BOOTTIME. Abrupt process death may lose this in-memory evidence. The production build has no recorder or clock reads for this feature. This observation does not change the three-second RPC deadline or qualify an aggregate reconciliation budget.

Helper failure sites use the same recorder and capacity, with side
`helper_stage` and a fixed stage code. They distinguish Open state/selection,
owner, gate staging/opening and forwarding; withdrawal closure, selection,
recovery, lease removal and readback; and nested authority/policy verification.
They retain no Work hash, address, path or raw error. Conditions keep their
original order, short-circuit behavior and call counts. The default build does
not even read the context through these diagnostic hooks.

The native fixture also collects new fixed-schema trace lines after the existing
supervisor Close returns. Its original control EOF, drain and four-second stop
bound are unchanged. This preserves helper output emitted after the initial
failure report. Missing earlier output alone does not prove a forced kill;
abrupt termination or the existing bounded log filling can still lose evidence.
No successful WAN acquisition or cause of a native failure is inferred here.

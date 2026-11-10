# Rule traffic observations

This laboratory extends administrative visibility without adding an inspection
engine. It records observations of the existing kernel rule counters. It does not
capture connections, packet payloads, individual packet timestamps or application
identity. Default-policy drops that match no explicit rule are not represented.

## Contract

`GET /api/v1/firewall/traffic?limit=50` requires an authenticated administrator.
The first page requests a fresh observation. Older pages use `before` and the
returned `stream`; they never sample traffic. The official CLI exposes the same
operation through `andeiva firewall traffic`. Web uses the same endpoint.

Each record contains a sequence, observation time, canonical revision, rule ID,
Allow/Deny action and cumulative packet/byte counters. Delta records additionally
contain the previous observation time and changes in both counters. Counter values
are decimal strings so that clients preserve the full unsigned 64-bit range.
An action describes the matched rule, not an independently inferred connection
outcome. Counters include both original and permitted reply directions.

A baseline contains observed totals with no delta. The first sample, API restart
or table replacement starts a new baseline. Reapplying the same configuration
also replaces the counter epoch. The helper binds that epoch to the same read as
the effective ruleset; revision comments alone are not sufficient verification.
Unverifiable or inconsistent observations cannot produce traffic records.

## Bounds and recovery

Sampling is manual and request-driven, not continuous logging. Intervals between
samples can include unobserved traffic; replacement can discard counters before
they are sampled. Observation times are not packet arrival times. There is no
claim of complete traffic accounting or a forensic event stream.

The API retains at most 512 records in memory. Oldest records are evicted and the
response reports that count. An expired pagination range is explicit. The stream
changes after an API restart; cursors from a previous stream are rejected. These
records are volatile and separate from the durable configuration audit journal.
No log file, background collector, retention daemon or host kernel log is added.

The observer has no policy-write authority. Reading these records cannot release
traffic or alter the host firewall. Only bounded, typed metadata crosses the
existing helper channel. The API and frontend retain their unprivileged roles.

## Verification

Unit and integration checks cover counter baselines, deltas, replacement epochs,
decreases, large counters, unavailable readback, concurrency, bounds, pagination
and permissions. Browser fixtures validate presentation and are not traffic
evidence. Native acceptance must correlate real TCP/UDP probes with explicit
Allow/Deny rules and read the same retained records through Web, CLI and API.
Restart acceptance must demonstrate a new stream and baseline while validating
configuration recovery separately. See the [milestone report](MILESTONE.md) for
execution status.

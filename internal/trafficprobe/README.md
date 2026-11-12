# Authorized client traffic probes

This package and `cmd/andeiva-traffic-probe` are development tools for an explicitly
authorized laboratory. They do not configure networking, run privileged commands,
scan a subnet, create listeners or decide whether a firewall rule permits traffic.
They are not administrative endpoints or the official `andeiva` management CLI.

Each invocation selects one IPv4 endpoint and a source IPv4 address already
assigned to the client. The source is bound for every connection and the actual
local/remote tuples are checked. Interfaces, routes, gateways and DNS settings are
never changed. `--authorized-lab` is an acknowledgement, not authentication or a
proof that the operator owns a destination. The operator must authorize the
specific destination and traffic before using the tool.

## Modes and evidence

| Mode | Observation | Limit |
| --- | --- | --- |
| `tcp` | One successful connection to the selected endpoint | Not a firewall verdict or an application check |
| `udp-echo` | Exact reply to a random 32-byte challenge | Requires a deliberately configured echo target; ordinary UDP services do not echo |
| `dns-a` | Successful IPv4 resolution plus observed DNS I/O | Returned values are not attributed to the DNS server; resolver/NSS may use local sources |
| `http-head` | One HEAD response, status and verified-TLS indication | Does not test a download, throughput, browser behavior or system DNS |

For HTTP, the URL hostname supplies Host/TLS identity while `--target-ipv4` selects
the only connection address; the URL port must match `--port`. There is no hidden
name lookup. Proxy environment variables are ignored, redirects are returned
without following them, persistent connections and HTTP/2 are disabled, response
headers are capped at 16 KiB and no response body is read. HTTP status codes are
application results, not firewall Allow/Deny decisions.

HTTPS always verifies certificates and hostnames with TLS 1.2 or later. By default
the Go runtime uses the current system trust store. An optional `--ca-file` must
be an independently trusted absolute regular PEM file, at most 1 MiB/256
certificates, without symlink ancestors or group/other write permissions. Identity
checks surround the bounded read. The explicit file replaces system roots for
that probe. Never obtain the trust anchor by trusting the first unknown TLS
server; there is no insecure verification switch. Linux rejects symlink/special
files without blocking on a substituted FIFO; other platforms refuse custom CA files and remain compile-tested
only and need native filesystem qualification.

DNS uses a fresh standard-library resolver, an explicit server endpoint and source
binding for both UDP and TCP. The transport list records attempts, connections,
source ports and bytes actually consumed/written, including UDP-to-TCP fallback.
It does not label every lookup UDP-only. `resolved_with_dns_io` means resolution
succeeded and DNS I/O occurred; `resolved_ipv4` always has
`resolution_source: "unattributed"`. It does **not** establish that those values
were returned by the selected server. For example, NSS `dns files` may receive
NXDOMAIN and then obtain values from a local hosts file. A controlled test seam
models that fallback after real loopback NXDOMAIN I/O without changing the system
hosts/NSS configuration. If resolution succeeds without DNS I/O,
`dns_not_observed` is returned with no values. Results are limited to 32 IPv4
values and 16 transport attempts. This is not a custom DNS resolver, wire-answer
verifier or DNSSEC verification claim. ASCII DNS names are accepted; international
names must already be valid ASCII/punycode.

## Bounds and interpretation

The timeout is positive and at most 15 seconds; cancellation reaches active socket
operations. Standard interface enumeration, trust-store loading and filesystem
reads are not preemptible, so the timeout is not a hard wall-clock or memory bound
for those OS/library calls. The standard DNS/TLS implementations have their own
internal allocation behavior. No background worker or retained history is added.

JSON contains stable outcomes and connection metadata, not URL paths, query
strings, credentials, challenge bytes or raw errors. URLs with userinfo, query or
fragment are rejected. Byte counts describe socket payload handled by this
process, including TLS or DNS framing where applicable; they are not packet,
Ethernet, per-rule or NAT counters. UDP receive truncation is a mismatch, not a
verified echo.
The UTC start timestamp uses the client's local clock; it does not attest clock
trust. Elapsed time measures this invocation, not a network throughput benchmark.

**A timeout, connection refusal or missing echo is not a Deny verdict.** Correlate
the selected tuples and time with real firewall counters, ruleset and translated
connection observations. A successful client operation alone does not prove NAT,
policy ownership or that traffic traversed ANDEIVA. In particular, do not run this
tool on the appliance itself and present that as a client-behind-firewall test.

Example templates (replace every placeholder with an authorized local value):

```sh
andeiva-traffic-probe --authorized-lab --mode tcp --source-ipv4 CLIENT_IP --target-ipv4 SERVER_IP --port SERVER_PORT --timeout 3s
andeiva-traffic-probe --authorized-lab --mode udp-echo --source-ipv4 CLIENT_IP --target-ipv4 ECHO_IP --port ECHO_PORT
andeiva-traffic-probe --authorized-lab --mode dns-a --source-ipv4 CLIENT_IP --target-ipv4 DNS_IP --port 53 --dns-name example.net
andeiva-traffic-probe --authorized-lab --mode http-head --source-ipv4 CLIENT_IP --target-ipv4 WEB_IP --port 443 --url https://example.net/ --timeout 5s
```

Do not put secrets in probe arguments. Help supports `--lang en|es|pt`; JSON keys
and outcome codes remain language-independent. Exit status is 0 for the four
positive observations, 1 for unsuccessful/neutral observations or output failure,
and 2 for invalid invocation. These exits do not encode Allow/Deny.

Build and run only loopback tests from the repository:

```sh
go test -race ./internal/trafficprobe ./cmd/andeiva-traffic-probe
go vet ./internal/trafficprobe ./cmd/andeiva-traffic-probe
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o /tmp/andeiva-traffic-probe ./cmd/andeiva-traffic-probe
```

Tests use temporary loopback listeners, controlled DNS UDP/TCP replies and trusted
test certificates. They do not contact Internet services or prove routed/NAT
operation. Actual client/Internet evidence remains a separate authorized lab gate.
See [Spanish](docs/es.md) and [Portuguese](docs/pt.md).

Custom CA files are supported only on Linux. Other platforms reject `--ca-file` before filesystem access with `invalid_ca_file`; system-trust HTTPS remains available with certificate verification. Native platform qualification is required before adding another safe opener.

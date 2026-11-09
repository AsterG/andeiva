# Security policy

ANDEIVA is in initial development. There are no supported appliance releases.
The current HTTP server exposes process health only and must remain in a local
development environment. Authentication and gateway security controls are not yet
implemented. Do not use this scaffold to protect a network.

## Reporting

Do not disclose vulnerabilities, credentials, captures or customer information in
public issues. During private development, report concerns through the existing
private project channel with the affected commit, reproduction steps and observed
impact. Remove sensitive data from examples.

A verified private vulnerability reporting channel must be configured before
opening the project for public contributions. There is no published response-time
commitment or supported-version policy yet. Both will be defined before a release.

## Changes requiring security review

Authentication, authorization, privileged operations, input handling, persistence,
dependency changes and network access require explicit threat analysis and negative
tests. A passing static scan alone is not evidence of production security.

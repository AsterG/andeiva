# Administration lifetime

The preview target requires the namespace manager and policy helper, but only wants the HTTPS socket and API. Stopping or failing the API/socket therefore leaves the last applied ruleset, namespace manager and independent helper lease alive. Explicit target shutdown and helper/namespace failure retain their existing coordinated shutdown paths. API restart limits still apply; availability can remain degraded without deleting the data plane.

Validation: `bash packaging/preview/tests/api-lifetime-unit-graph.sh`. This checks dependency direction, not live traffic or real systemd failure behavior; those require isolated Debian qualification.

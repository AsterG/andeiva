# Validation workflows

`quality.yml` checks repository policy, Go formatting/vet/tests/race, frontend
lint/types/tests/build, workflow syntax, Linux amd64/arm64 compilation and Docker
smoke execution. Cross-compilation does not establish target hardware support.

`security.yml` runs secret detection, Go static/vulnerability analysis, npm audit
and dependency inventories. It scans development dependencies as well as runtime
dependencies. Inventories are private workflow artifacts with seven-day retention;
they are not a signed appliance SBOM or redistribution approval.

All jobs use read-only repository permissions and actions pinned to commit hashes.
No deployment, package push, release, signing key or privileged host operation is
configured. Pull requests do not receive deployment secrets. Dependency upgrades
require review; build-time registry access does not enable appliance online updates.

Enable required checks and reviewer protection in repository settings before merging.
Local checks do not prove that GitHub-hosted workflows have executed. Runtime,
fault-injection, offline update and target-hardware gates will be added with the
corresponding implementation, without placeholder passing jobs.

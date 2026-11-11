# Changelog

## Unreleased — unified administration console

- Rebuild with the Go 1.27.4 security patch and its pinned development image;
  update current build instructions while retaining historical benchmark records.

- Restore individually associated address and port guidance in the rule editor;
  keep labels, hints and validation errors linked with unique field identifiers.
- Preserve the rule identity field's full width using a layout class independent
  of generated accessible identifiers, with responsive Light/Dark geometry checks.
- Lock column visibility, filters and revision controls during rule reordering,
  preserving pointer capture, keyboard cancellation and the local draft.

- Isolate sign-in from administrative navigation during session lookup, rejected
  access, logout and expiry, including direct firewall and local-service URLs.

- Open the authenticated console at the management root address, with compact
  navigation for Dashboard, Rules, Audit, Configuration and Traffic records.
- Preserve the shared session and local editor across views; add contextual
  transaction actions, configurable rule columns and readable revision details.
- Keep Light as the default, optional Dark, EN/ES/PT and the unchanged logo.
  Show unavailable telemetry explicitly rather than inventing dashboard values.
- Include multilingual console guides in the experimental Debian package;
  keep component examples at the explicit design-system preview address.

## Unreleased — confirmed transaction capacity

- Reserve journal and receipt capacity before a confirmed transaction changes
  an engine, preserving confirmation, timeout rollback and one recovery cycle.
- Prevent ordinary writes and rejected-request audits from consuming that
  pending reservation. Preserve existing quotas, journal formats and replay.
- Keep lifetime retention and recovery of already exhausted stores as separate
  limitations; this change does not compact or delete protected history.

## Unreleased — rule activation and administration table

- Retain explicitly disabled forwarding rules in the versioned transaction
  contract while compiling and observing only active rules.
- Add a compact rules table with accessible drag ordering, a side editor and
  separate Running and Startup indicators for content, activation and order.
- Preserve legacy revision hashes and require explicit executor capabilities
  before enabling the new rule-state contract in Web, CLI and API.
- Record isolated Debian traffic and browser validation, resource observations
  and limits in [the validation report](frontend/docs/firewall-rule-validation.md).
  Updating source or CI does not deploy the installed Alpha appliance.

## Unreleased — isolated local service administration

- Manage HTTPS and restricted SSH declarations through authenticated Web, CLI
  and API operations sharing Candidate, Running, Startup, audit and recovery.
- Reconcile generated Local-In rules with nftables and independently observed
  listeners; require bounded recovery and endpoint proofs before confirmation.
- Add an explicit Debian laboratory runner with separate process identities,
  a fixed recovery endpoint and three owned network namespaces.
- Keep host SSH, host firewall, forwarding and installed Alpha services outside
  this experiment. Native acceptance remains subject to the validation report.

## Unreleased — isolated local service policy compiler

- Separate appliance-local input declarations from forwarding with typed service
  ownership, explicit sources, LAN defaults and per-binding WAN opt-in.
- Add deterministic IPv4/IPv6 TCP/UDP compilation, impact previews, dependency
  validation and comparison of supplied rule/listener observations.
- Document limits and future transaction integration in EN/ES/PT; test capacity,
  permission scope, concurrency and malformed input without activating services.
- Keep runtime selectors, shared-schema migration, kernel enforcement and
  administrative recovery outside this compiler-only change.

## Unreleased — persistent Firewall Alpha Preview

- Package the existing administrative workflow for Debian 13 AMD64 with separate
  API, namespace lifecycle and narrowly authorized helper services.
- Bind HTTPS to an explicit address and interface with a client source ACL;
  retain isolated enforcement and verified configuration recovery.
- Add explicit provisioning, protected persistent state, readiness checks,
  reproducible package controls and EN/ES/PT procedures.
- Record native laboratory acceptance and its limits in
  [the validation report](packaging/preview/VALIDATION.md); no host firewall or
  production readiness is claimed.

## Unreleased — rule traffic observations

- Add administrator-only, on-request rule counter records shared by Web, CLI and
  API, with explicit baselines, replacement epochs and exact 64-bit totals.
- Bound the volatile history to 512 records; report eviction, reject stale-stream
  cursors and keep connection/payload logging outside this experiment.
- Add EN/ES/PT presentation, permission and pagination tests, and Light/Dark
  visual coverage without changing the approved logo or network policy scope.

## Unreleased — authenticated firewall administration laboratory

- Add a shared schema for ordered IPv4 TCP/UDP rules and strict kernel readback.
- Add authenticated HTTPS administration, CLI commands and a localized Web editor
  using the existing Light/Dark Design System and unchanged official logo.
- Reuse the transactional engine with independent helper leases, explicit save,
  historical rollback, audit and fail-closed recovery after uncertain publication.
- Keep privileged operations in an isolated namespace helper with separate
  operator/runtime identities, bounded HTTP admission and supervised cleanup.
- Add unit, fault, race and visual regression coverage plus EN/ES/PT procedures.

## Unreleased — nftables laboratory adapter

- Add a typed immutable fixture catalog, strict JSON compilation/readback and
  three isolated namespaces for real TCP/UDP allow/deny experiments.
- Coordinate confirmed commits with an independent rollback lease; block
  mutations after unprovable confirmation and reject invalid helper responses.
- Add negative, concurrency and process-recovery tests, unprivileged CI checks,
  and EN/ES/PT procedures with bounded Debian execution measurements.
- Keep the adapter isolated from appliance traffic and production management.

## Unreleased — Design System

- Centralize complete Light/Dark themes, with Light as the default and explicit
  browser-local preference restored before the application renders.
- Add shared accessible UI primitives and a responsive component library with
  English, Spanish and Portuguese copy; preserve the approved logo unchanged.
- Add semantic color/contrast gates and pinned-browser visual, keyboard,
  accessibility and responsive checks for both themes.

## Unreleased

- Registered staging for the configuration experiment, independent of temporary
  filename conventions, with bounded recovery and preservation of unknown files.
- Cross-platform source-selection checks and the initial nftables experiment
  proposal, followed by the bounded laboratory adapter described above.

- Isolated transactional configuration experiment with simulated engines, shared
  authorization checks, local persistence, failure tests and resource observations.
  Includes regression coverage for failed boot compensation, orphan staging
  recovery and rejection of invalid output paths before directory creation.

- Initial Go CLI and development HTTP liveness server with EN/ES/PT command output.
- React/TypeScript development page with language selection and light default theme.
- Source, test, security and build validation workflows.
- Local container smoke configuration and contributor documentation.
- Experimental native Debian 13 amd64 packaging with a restricted systemd service,
  lifecycle tests, reproducibility checks and EN/ES/PT installation guides.

No appliance release or production gateway capability is available.

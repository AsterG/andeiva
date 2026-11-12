# Changelog

## Unreleased — internal composite transaction coordinator

- Coordinate firewall changes against durable operations with atomic outcome/state/audit selection and verified component readback.
- Preserve independent domain projections, explicit Startup, confirmed-commit recovery and verified rollback targets.
- Add simulated-engine interruption and endurance tests; runtime activation and administrative transport integration remain disabled.

## Unreleased — inactive routed network configuration model

- Report a single stable field path for schema, collection and field-size validation errors.

- Validate bounded WAN/LAN/management IPv4 configuration, interface bindings, zones,
  default route and DNS before execution. Preserve host bits and deterministic
  revisions; never infer DHCP leases from observed addresses.
- Add strict JSON control-field validation and reuse exact JSON checks for nft
  observations. No interface, route, DNS or forwarding changes are activated.

## Unreleased — custom CA platform safety

- Reject custom CA files before filesystem access on platforms without a qualified
  nonblocking, no-follow opener. Keep verified system-trust HTTPS available.
- Test Linux FIFO/symlink substitutions and non-Linux refusal.

## Unreleased — inactive configuration storage v2 foundations


- Reject invalid checkpoint/segment boundaries and mismatched historical state lineages during reopen.

- Prepare immutable selected storage, a bounded durable operation catalogue and
  cold schema 3/4 migration without activating engines or administrative endpoints.
- Preserve legacy configuration and replay provenance; test interruptions, registry
  retirement, concurrency and exact lookup. Physical reclamation and cutover remain
  unavailable.
- Finalize expired/closed operations and linked pins from their own released
  reservations, preserving other pending reservations through write failures.

## Unreleased — authenticated configuration v2 adapter

- Bind configuration operations to verified sessions and canonical durable subject identities.
- Revalidate session expiry/revocation and atomic registry ownership on every request; preserve legacy unbound authentication.
- Expose the existing coordinator through bounded adapters without activating public transports or migration.

## Unreleased — internal read-only network inventory

- Observe real interfaces, IPv4/IPv6 addresses, masks and link flags through an
  internal read-only collector, with conservative device classification and
  explicit limits. Do not infer roles, gateways, DNS or connectivity.
- Detect observable changes between readings and cover invalid observations,
  cancellation and concurrency. Administrative integration remains separate.

## Unreleased — journal append publication safety

- Publish authoritative journal records with atomic no-replace semantics and
  verified directory descriptors; refuse unsupported operations without fallback.
- Preserve competing destinations and reject changed staging identity before
  publication. Cover publication races, process exits and v1 reopening.

## Unreleased — bounded client traffic observations

- Add a development-only, unprivileged one-target client for TCP, UDP echo,
  explicit-server DNS I/O and pinned-endpoint HTTP(S) HEAD observations.
- Validate local source ownership, preserve TLS verification, avoid proxies and
  redirects, bound output and distinguish timeouts from firewall verdicts.
- Document un-attributed resolver results and loopback failure cases in EN/ES/PT.
  The tool does not configure networking or establish NAT or firewall enforcement.

## Unreleased — prepared configuration operations transport

- Prepare strict HTTPS operation contracts and a bounded client with atomic global/domain observations.
- Add explicit cold-migration inspection and fingerprint checks without changing legacy sources.
- Qualify real-store transport tests with simulated engines; production routes and capabilities remain disabled.

## Unreleased — checkpoint publication safety

- Publish checkpoint images atomically without replacing an existing destination,
  including one created after the initial existence check.
- Refuse unsupported no-replace operations and preserve staging data and the
  previously selected checkpoint on publication conflicts.

## Unreleased — internal checkpoint preparation

- Prepare two validated checkpoint images and an atomic selection manifest in a
  separate private area while retaining the authoritative v1 journal and receipts.
- Refuse unsafe or overlapping workspaces and verify the originally synchronized
  file before publication. Add interruption, process-exit and corruption tests.
- Keep preparation disconnected from runtime mutations; compaction, migration,
  protected-history reclamation and storage continuity remain separate work.

## Unreleased — experimental offline boot dependency bundle

- Add a development-only Debian 13 AMD64 bundle builder and offline verifier,
  with a reviewed dependency profile, signed Debian metadata checks and a closed
  checksum inventory. Installation requires a compatible baseline and verified
  recovery; this is not the signed appliance update format.
- Coordinate package installation with boot activation through protected locks
  and a durable pending marker, retain recovery evidence after failures and bound
  installer output without enabling network package downloads.

## Unreleased — offline boot installation coordination

- Expose the local activation tool's offline-install guard capability and refuse
  boot mutations while an installation marker remains, including after its
  process loses the shared lock. Keep status and capability queries available.
- Add failure and process-interruption tests and a guard-only native laboratory
  test that does not install packages or run APT.

## Unreleased — recovery-gated boot activation

- Add an explicit local experimental boot-theme activation and restoration tool,
  with recovery preflight, protected backups, serialized changes and a retained
  previous kernel. Native boot qualification remains separate from fixture tests.
- Preserve the original logo while using a proportional GRUB display copy to
  keep boot and recovery choices visible at low resolutions.
- Show failed systemd units without printing successful boot-status lines.
- Validate storage layout by capabilities instead of a device label, and provide
  an explicit temporary diagnostic boot with private bounded traces in RAM.
- Add an opt-in graphical redraw compatibility mode, without forcing a display
  resolution or changing drivers; preserve the default and recovery configuration.

## Unreleased — prepared transactional engine guards

- Arm fixed engine leases after durable intent and verify exact receipts and effective state before confirmation.
- Reconcile owned expired leases with verified compensation while retaining fences for ambiguous confirmed publication.
- Qualify simulated-engine and in-process guardian recovery without enabling privileged runtime integration or OS-boot migration.

## Unreleased — inactive boot theme resources

- Add GRUB and Plymouth theme resources with the original logo, English status
  text and an indeterminate activity indicator, plus reproducible package checks.
- Keep theme selection, bootloader changes and initramfs activation separate;
  native boot and recovery qualification remain pending.

## Unreleased — compact administrative header

- Move account information and sign-out to the top header, separate from
  configuration operations, with compact language and appearance preferences.
- Share accessible, localized menus across administrative and sign-in views;
  support keyboard dismissal, focus return, zoom and small screens in both themes.

## Unreleased — configuration storage admission

- Check available filesystem bytes and inodes before ordinary configuration
  mutations, without consuming the existing critical recovery path.
- Add isolated finite-filesystem checks; this does not implement compaction,
  protected audit retention or a physical recovery reserve.

## Unreleased — product version visibility

- Show the authenticated appliance product version in System and the navigation
  footer, with equivalent CLI/API reads and explicit unavailable update status.
- Stamp preview backend and CLI identities from the Debian package version and
  verify that identity during package validation.
- Correct relative links from packaged console guides to the EN/ES/PT package
  guides, preserving their section anchors.
- Remove general laboratory-scope banners from the web interface while retaining
  contextual errors, authorization, confirmation and recovery controls.

## Unreleased — movable rule editor

- Open a centered movable desktop editor, with mouse, touch and keyboard controls,
  and a viewport-sized modal editor on small screens. Preserve drafts across
  navigation, explain blocked actions and retain session and transaction guards.
- Add Light/Dark responsive captures and movement, focus and recovery regressions.

## Unreleased — verified journal reads

- Retain lightweight journal metadata and the latest durable state instead of
  keeping every historical configuration snapshot in memory.
- Verify historical records on demand without changing the journal format,
  authenticated retry behavior, revision history or recovery reservations.
- Keep lifetime capacity and full-volume recovery as unresolved limitations;
  this preparation does not compact, expire or delete protected records.

## Unreleased — bounded login admission

- Clarify the shared verified-login allowance for valid compatibility logins;
  cover mixed entry points and give invalid SSH peer cases distinct test names.
- Separate anonymous and verified login allowances using the receiving HTTP/SSH
  socket peer, a fixed origin table and unchanged required audit/session controls.
- Preserve verified access under anonymous allowance exhaustion, including a
  shared source address; keep persistent audit exhaustion as a separate limitation.
- Add negative, concurrent and verified loopback TLS tests and EN/ES/PT guidance.

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

## Unreleased — isolated local service administration

- Manage HTTPS and restricted SSH declarations through authenticated Web, CLI
  and API operations sharing Candidate, Running, Startup, audit and recovery.
- Reconcile generated Local-In rules with nftables and independently observed
  listeners; require bounded recovery and endpoint proofs before confirmation.
- Add an explicit Debian laboratory runner with separate process identities,
  a fixed recovery endpoint and three owned network namespaces.
- Keep host SSH, host firewall and forwarding outside
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

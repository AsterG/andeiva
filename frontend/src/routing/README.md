# Routed configuration workspace

This workspace uses the authenticated configuration v2 capability. It does not
migrate storage, grant privileges, or enable a runtime by installing the frontend.
The existing firewall view remains available on endpoints without that capability.

Network, forwarding rules, source NAT and local access share one selected
configuration. Local edits remain in the browser until Prepare; Validate performs
server checks. Apply requires confirmation within 30–120 seconds. Confirm uses the
original operation and composite revision. Save persists the complete Running
configuration for restart; restoring Startup also requires confirmation.

The network editor currently supports two statically addressed interfaces. It
refuses to overwrite a DHCP or larger topology. Source NAT does not authorize
traffic: an independent Allow rule is required. Rule order is global, first-match;
clear the search before reordering. Keyboard dragging uses Space, arrows, Enter
and Escape. Disabled rules remain configured without evaluating traffic.

An uncertain execution blocks new writes. Check the retained operation ID; only
an accepted request offers an explicit execution action. No automatic execution
retry or v1 write fallback occurs. Terminal operations close their namespace.
Effective status requires kernel observation matching the current generation and
revision; selected configuration alone is not evidence of successful activation.

Browser tests use explicitly synthetic transport fixtures, not packet-enforcement
evidence. They cover EN/ES/PT, Light/Dark, responsive layouts, keyboard interaction,
accessibility and interrupted execution. Native runtime and traffic qualification
remain separate requirements.

The audit view uses administrator-only protected records. Filters combine on the
loaded page; pagination preserves exact decimal sequences. A scan is bounded to
1024 records and 2 MiB, and incomplete scans are explicitly reported. Display names
come from the current registry; durable actor IDs remain available in details.
Historical records without channel provenance are not assigned a Web/CLI/API
origin. The view does not infer traffic events from configuration audit records.

```sh
npm run lint
npm run typecheck
npm test
npm run build
npx playwright test routing.spec.ts --workers=1
```

See [Spanish](docs/es.md), [Portuguese](docs/pt.md) and the
[CLI contract](../../../internal/cli/CONFIGURATION_V2_EN.md).

Retained schema4 rules use the existing rule table and editor without inventing
a network plan. Grouped candidates can be explicitly replaced or discarded after
review, with the exact prior stage ID and global generation. Stage never replaces
an existing candidate. The server enforces durable ownership; controls do not
grant permission. Neither operation applies traffic changes. Historical candidate
bases remain visible; Validate and Commit stay blocked until explicitly replaced.

## LAN DHCP settings (DHCP-LAN-WEB-001)

Network includes a DHCP scope editor for selected static LAN interfaces. Adding
settings explicitly upgrades the routed policy from version 1 to version 2 with
`dhcp_server`; untouched version 1 documents retain their original bytes. Disabling
DHCP preserves its settings. The editor validates pools, exclusions, reservations,
DNS/NTP, domain and lease/T1/T2 bounds, including disabled scopes. Network edits
that invalidate an existing scope are rejected; update or remove that scope first.
The server remains authoritative for validation, authorization and runtime support.

Changes enter the shared local draft and existing Prepare, Validate, confirmed
Apply, Confirm and Save operations. No extra store, endpoint, polling or forwarding
permission is introduced. Configuration enablement does not prove a running
service or assigned leases. Unsupported runtime errors remain visible. This UI
does not activate WAN DHCP and does not display lease telemetry.

Run `node --test tests/dhcp-configuration.test.mjs` after `npm test` and
`npx playwright test dhcp-settings.spec.ts routing.spec.ts` after the build.
The browser fixtures test EN/ES/PT, both themes, three viewport sizes, accessibility,
viewer restrictions and rejected server admission; they are not native DHCP proof.
Rollback of this frontend change means reverting its commit; committed policy-v2
data requires a compatible reader and must not be silently downgraded to v1.

To edit: open Network → Add scope, select a static LAN, enter a scope ID and
usable pool range, then optional exclusions/reservations/DNS/NTP/domain and lease
timers. Keep the scope in local draft. Enable only through the explicit checkbox;
review and Prepare changes using the shared transaction controls. Validation and
application may reject unsupported runtime configurations. Confirm successful
application before Save for restart. No lease test is implied by these steps.

Validation on 2026-11-14: Docker `check-web` passed lint, typecheck, 71 unit tests,
build and byte-for-byte logo comparison; `docker compose config --quiet` passed.
The isolated browser run passed 72 DHCP/routing tests (12 new), with zero Axe
violations for the checked scopes and Light/Dark screenshots at 1440, 768 and
390 pixels. Screenshots were visually inspected, including scrolling to the
mobile reservation/timer controls. Fixtures are explicitly synthetic.
The final parser-only addition for a valid zero-base /1 subnet was rechecked by
the unit suite and Docker build; it does not change the captured layout.

Against baseline `804cb6a`, the production JavaScript bundle changed from
451.43 kB / 134.83 kB gzip to 467.69 kB / 139.74 kB gzip; CSS changed from
40.84 kB / 7.41 kB gzip to 41.21 kB / 7.48 kB gzip. No dependencies, polling,
runtime services, environment variables or infrastructure were added. Sustained
browser CPU/RAM and native DHCP qualification remain pending. EKS/Helm and the
appliance runtime are unchanged. Independent review remains a merge gate.

### DHCP editor context guard

Refresh and transaction/reset actions are blocked while a scope editor is open.
The editor captures its exact draft and server snapshot. Replacing either,
losing edit permission or leaving Network invalidates the open editor before it
can save, independently of the button guards. Existing shared local edits remain
intact; unsaved scope-form input is not rebased onto a new server generation or
scope index. Logout unmounts the editor with the administrative workspace.

The review fix passed lint/typecheck, 71 unit tests and Docker `check-web` including
logo comparison. Browser coverage comprises 99 cases: 98 passed in the combined
run; a test that sent Escape outside the modeless editor was corrected to focus
its input, and all three workflow variants passed in the focused rerun. The 24
context-invalidation cases cover reordered responses, snapshot/generation changes,
draft reset, network replacement, permission loss, write blocking and logout.
These component tests bundle their explicit fixture in memory with Vite; no test
route or hook ships in the application. Light/Dark desktop/mobile screenshots
were reviewed again. The final bundle is 467.85 kB / 139.88 kB gzip JavaScript;
CSS remains 41.21 kB / 7.48 kB gzip. Reproduce with
`npx playwright test dhcp-context.spec.ts dhcp-settings.spec.ts routing.spec.ts`.

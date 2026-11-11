# Administration console

Before authentication, only the access screen, original logo, language and theme
selectors are rendered. Administrative menus and views are mounted only after a
valid session is verified, and removed on logout, expiry or a rejected session.
This presentation boundary complements server-side authorization; it does not
replace API authentication or RBAC.

Open the appliance HTTPS address to enter the authenticated console. `/firewall`
remains supported. Navigation uses `#dashboard`, `#rules`, `#audit`,
`#configuration` and `#traffic`; it does not create a second session or stage
configuration when changing views. The component examples are separate at
`/?view=design-system` and do not represent appliance state.

The dashboard derives rule counts from Running and packet/byte totals from the
last verified effective revision. Totals are observations, not rates or individual
connections. Geographic traffic, interface RX/TX rates, CPU and memory remain
unavailable when the API supplies no corresponding observations. The map is
static geography. There are no invented traffic flows or country rankings.

Edit rules in the side panel. The current runtime supports IPv4, TCP/UDP,
inclusive source/destination port ranges, Allow/Deny and capability-gated
enablement. Reusable address objects, FQDN groups and application identification
remain unavailable. Changing views preserves an unsubmitted editor and the local
draft; signing out or session expiry clears them. Rules can be reordered with
the pointer, touch handle, keyboard or explicit position. Filters and an open
editor prevent ambiguous reordering.

Stage publishes the local draft as Candidate. Validate checks Candidate; Commit
with confirmation applies it to Running and schedules automatic reversal unless
confirmed. Save stores all of Running as Startup for the next system boot.
Restarting a service is not equivalent to a system boot. The action menu contains
the confirmation timeout, immediate commit, local-draft discard and technical
revision details. Discard does not delete the persisted Candidate.

Audit is administrator-only. Filters cover the loaded page, not the entire
journal. Dates use the browser's local calendar, consistently with displayed
timestamps. Inspect an event for its recorded actor, client, result and full
revision. Expand confirmed revisions to review and request rollback. Configuration
compares order and enforcement fields across Candidate, Running and Startup.

Light is the default; Dark is an explicit saved choice. EN/ES/PT are available.
The approved logo is unchanged. Browser tests use labeled transport fixtures;
they do not prove backend authorization or packet enforcement. Native validation
must use the authorized Debian laboratory before deployment.

Run `npm run lint`, `npm test`, and `npm run build` from `frontend`. Build the
canonical browser environment from the repository root with
`docker build -f frontend/Dockerfile.visual -t andeiva-console-check .`, then run
`docker run --rm --network none --shm-size 256m andeiva-console-check`.

Rule-editor address and port fields expose individual guidance and validation errors to assistive technology. During reordering, column visibility, filters, revision selection and explicit position changes are locked until drop or cancellation. Escape cancels the move; changes remain local until explicitly staged.

## Product version

After signing in, open System → About ANDEIVA to read the installed product version. The navigation footer shows the same authenticated value. Development builds and unavailable metadata are explicit. No update availability is inferred. See the [package guide](../../packaging/preview/docs/en.md#installed-product-version) for the matching CLI query and local-versus-remote identity.

# Local Services administration

`/local-services` consumes the authenticated Local Services API. It shows the
module only when the runtime reports the capability. It uses the existing
Design System, unchanged logo, manual Light/Dark selection and EN/ES/PT strings.
The default remains Light regardless of system preferences.

System → Local Services edits the declared HTTPS and restricted SSH services.
The interface inventory comes from the server; the browser does not discover or
invent interfaces. Source CIDRs, WAN intent, bindings and high TCP ports are
validated before staging, then validated authoritatively by the shared backend.
There is no forwarding rule editor on this page. Generated Effective Policies
are read-only and filtered by service, interface, protocol, port and source.

Edits remain an unsaved browser draft until Stage. Validate checks the candidate.
Commit and historical rollback always request a 30–120 second confirmation
window. Save explicitly persists Running to Startup. Unknown effective state,
stale generations and another administrator's candidate prevent writes.
Filtered effective policies must match the loaded Running revision and its
confirmation phase. An unavailable, blocked or mismatched response invalidates
the view and disables writes until a full status refresh succeeds; unknown
state is never displayed as an empty verified ruleset.

Changes use the fixed authenticated recovery endpoint. Immediately before an
activation, confirmation or Save, the page obtains a short-lived recovery proof
in the same session. Confirm also requires a real authenticated proof from each
enabled binding. At a managed HTTPS endpoint, sign in and use the pending
revision's proof panel; restricted SSH obtains its proof through the CLI.
Copy those opaque tokens back to the recovery console. If all managed services
are disabled, no managed-endpoint proof is needed. The backend binds proofs to
the actual listener activation; client booleans, URLs and headers cannot attest
connectivity. The browser never fetches arbitrary confirmation URLs.

Proofs and credentials are not put in URLs, logs or browser storage. Issued
proofs clear on expiry, refresh, logout and session failure. A lost response
does not display a successful or verified state; refresh and inspect the
backend's durable revision before attempting another change.

Tests use explicitly identified HTTP fixtures for UI behavior. They do not prove
real authentication, listener operation or kernel filtering. Native Debian
evidence is an independent integration gate.

```sh
npm run lint
npm run typecheck
npm test
npm run build
npm run test:e2e -- e2e/local-services.spec.ts
```

Visual baselines must be generated and compared in the pinned
`frontend/Dockerfile.visual` environment. Desktop, tablet and mobile cover both
themes; accessibility checks cover the visible form and translations. Existing
baselines for other modules must not be regenerated to hide unrelated changes.

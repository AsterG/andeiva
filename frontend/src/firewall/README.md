# Firewall administration UI — FW-ADMIN-001

Route `/firewall` uses the shared ANDEIVA primitives, unchanged approved logo,
English default, EN/ES/PT copy and explicit persisted theme choice. The original
development overview remains at `/`.

This module is an authenticated **laboratory** client. It does not provide host
firewall administration, content inspection, security profiles, production
authentication or packet enforcement. The server and isolated dataplane supply
the actual results; test fixtures exist only in `e2e/firewall.spec.ts`.

## Data and security boundaries

- Same-origin `/api/v1` requests include `X-ANDEIVA-Client: web`; writes include
  the session's `X-CSRF-Token`. The server sets the Secure HttpOnly session cookie.
  Browser storage contains no credential, session token, CSRF value or policy.
- Provisioned random credentials are submitted once, then the input is cleared.
  Session expiry clears sensitive views and invalidates in-flight results.
  Redirects are rejected; requests time out after 15 seconds without automatic
  transaction retries. Serve the application from the trusted laboratory HTTPS
  origin. This client does not bypass certificate validation.
- Server response shapes, schema versions 2 and 4, rule bounds, canonical IPv4 prefixes,
  port bounds and revision hashes are checked before rendering. React escapes
  text. Server error text is never rendered; stable codes map to localized copy.
- The server enforces roles. Viewer controls are read only; privileged history
  disappears when access is denied. UI control visibility is not authorization.
- Local edits are separate from Candidate, Running and Startup. Rule array order
  is priority; IDs are unique; there are at most 64 rules. IPv4 host addresses
  become `/32`; CIDRs are normalized visibly in the local draft before staging.
- Writes carry a new UUID idempotency key and the observed generation. Stale
  drafts require an explicit discard/review. No failed write is silently retried.
  Commit, confirm, save and historical rollback show an operation/revision review.
- Confirm binds the exact running hash; rollback binds a server-listed revision.
  Confirmed commit supports 30–120 seconds, encoded as nanoseconds for the API.
  Its deadline invalidates displayed effective status; refresh obtains recovery.
- A disconnected, inconsistent or unavailable effective observation blocks writes.
  A successful transaction is re-read before showing completion. Counters appear
  only for the displayed revision that matches the effective observation. Status
  always identifies the time of the last manual refresh; there is no polling.
- History is bounded to one 50-entry server page. Actor/revision, operation and
  result filters combine with AND and apply to that page only.

## Rule workspace

The rule table, editor and transaction controls share the existing theme tokens.
Pointer dragging changes only the browser draft. Keyboard users can pick up a
handle with Space, choose a position with arrows/Home/End, place with Enter or
cancel with Escape. The row action menu also accepts an explicit position.
Filtering blocks reordering so hidden rules cannot receive ambiguous priorities.
An open editor blocks reordering and other row edits until saved or cancelled.

The execution and Startup columns compare each displayed rule's content,
enablement and position. A matching row does not prove that the entire revision
matches; the separate revision status reports that distinction. Save always
stores the complete Running revision. Running is journaled and may survive a
service restart; it is not simply volatile RAM. Startup is used for appliance boot.

Disabled-rule controls require the runtime's explicit
`firewall_rule_enabled: true` capability and support for schema 4 in
`firewall_config_schema_versions`. Missing or unavailable capabilities leave
those controls disabled by omission. Legacy schema 2 retains its original wire
shape. Editing enablement migrates the local draft to schema 4, with an explicit
boolean on every rule; Stage, Validate, Commit/Confirm and Save retain their
existing contracts. Disabled rules remain ordered configuration records and
have no effective packet counters; the UI displays “Not applicable”.

Operator guides: [English](docs/rules-en.md), [Español](docs/rules-es.md),
[Português](docs/rules-pt.md).

Browser fixtures demonstrate interaction and rendering only. They do not prove
native nftables enforcement, authorization, persistence or recovery.

## Reproducing checks

Run from the repository root with the existing pinned dependencies:

```sh
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
docker build -f frontend/Dockerfile.visual -t andeiva-design-check .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true --shm-size=512m andeiva-design-check
```

The browser tests cover transactional requests, rules, ordering, role visibility,
input errors/focus, stale generations, disconnects, session expiry, inconsistent
responses, deadlines, history filters, light/dark screenshots and automated
accessibility across desktop/tablet/mobile and EN/ES/PT. Mocks verify client
behavior only; real TLS/auth/RBAC/audit/packet tests belong to native integration.
Automated accessibility checks do not replace assistive-technology review.

This frontend consumes the versioned backend capability and schema 4 contract;
it cannot enable unsupported runtime operations. No dependency, package lock,
shared design tokens, runtime listener, container privilege or EKS/Helm
configuration is changed. Bundle sizes
are measured during the build. Browser CPU/RSS and real laboratory integration
remain separate acceptance gates. Revert this feature's commit to roll back the
UI; policy journals and effective firewall configuration are unaffected.

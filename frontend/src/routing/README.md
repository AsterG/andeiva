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

```sh
npm run lint
npm run typecheck
npm test
npm run build
npx playwright test routing.spec.ts --workers=1
```

See [Spanish](docs/es.md), [Portuguese](docs/pt.md) and the
[CLI contract](../../../internal/cli/CONFIGURATION_V2_EN.md).

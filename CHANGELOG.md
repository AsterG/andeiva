# Changelog

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
- Cross-platform source-selection checks and an isolated nftables experiment
  proposal; no real firewall adapter is implemented.

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

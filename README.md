# ANDEIVA Security Gateway

![ANDEIVA Security Gateway](frontend/public/andeiva-logo.png)

ANDEIVA is an ASTERG project in early development. This repository contains the
Go backend and CLI, a React/TypeScript interface, and validation workflows. An
isolated Debian laboratory provides authenticated Web/CLI/API rule administration
and real nftables enforcement in disposable namespaces. It is not a production
firewall, appliance installer or update mechanism. Traffic inspection and VPN are
not implemented. Native packaging and configuration experiments are described below.

The intended appliance base is Debian 13. Container targets below are development
checks, not appliance images. Web, CLI and API functional parity is a requirement
for management features. The administrative laboratory and the original liveness
scaffold are separate entry points; see the laboratory's validation report for
tested behavior and limitations.

## Source layout

| Path | Purpose |
|---|---|
| `cmd/andeiva` | CLI entry point |
| `cmd/andeiva-api` | Development liveness server |
| `internal/cli` | CLI parsing, localized output and tests |
| `internal/httpserver` | Bounded HTTP server, local probe and tests |
| `internal/configpoc` | Experimental transaction coordinator and simulated engines |
| `cmd/andeiva-config-poc` | Isolated configuration experiment runner |
| `frontend` | React/TypeScript source, translations and tests |
| `scripts` | Repeatable source and build checks |
| `.github/workflows` | Quality and security checks; no publishing |

## Development

Use Go 1.27.4 and Node.js 24.20.0 with npm. Commands for Linux/WSL:

```bash
npm --prefix frontend ci --ignore-scripts --no-audit --no-fund
bash scripts/check.sh
go run ./cmd/andeiva --lang en status
go run ./cmd/andeiva-api
```

In another terminal:

```bash
curl --fail http://127.0.0.1:4000/healthz
go run ./cmd/andeiva-api --healthcheck
npm --prefix frontend run dev
```

The API defaults to `127.0.0.1:4000`. `ANDEIVA_LISTEN_ADDR` accepts an explicit
numeric IP and port. Health reports process liveness only, never gateway readiness.
No management routes or credentials exist. Keep this unauthenticated scaffold local.
Stop the development server with Ctrl+C; it drains requests before exit.

The page starts in English and light mode, with Spanish/Portuguese and an explicit
dark option. Theme preference is local to this development page, not an account
setting. No remote fonts, analytics or appliance connection are required.
The approved logo is bundled locally and displayed without cropping or recoloring
in either theme.

The development interface includes a component library for forms, filters, tables,
status indicators and dialogs. These are local UI examples, not appliance controls.
All views use the [shared Design System](frontend/DESIGN_SYSTEM.md), with complete
Light/Dark semantic tokens and an explicit light branding surface for the original
logo. New modules must use these components and pass the theme, contrast, keyboard,
responsive and visual comparison gates. See the [frontend audit](frontend/DESIGN_AUDIT.md)
and contributor guides in [Español](frontend/docs/design-system-es.md) and
[Português](frontend/docs/design-system-pt.md).

Visual regression checks use the same pinned browser container locally and in CI:

```bash
docker build -f frontend/Dockerfile.visual -t andeiva-design-check .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true --shm-size=512m andeiva-design-check
```

The tests cover both themes at desktop, tablet and mobile sizes. Automated
accessibility checks and keyboard assertions are not a complete screen-reader
assessment or a WCAG certification. Baseline updates require explicit visual review.

## Experimental native Debian package

The native packaging experiment installs the Go API and `andeiva` CLI on Debian 13
AMD64. It runs the API under a restricted systemd identity on loopback; it does not
install a firewall, web administration server, inspection engine or boot theme.
The package is unsigned and intended for an isolated development VM with recovery
available. It is not the appliance installer or a signed offline system update.

Build, verification and lifecycle instructions:
[English](packaging/debian/docs/en.md), [Español](packaging/debian/docs/es.md),
[Português](packaging/debian/docs/pt.md). Docker is not required in the Debian guest.

## Persistent Firewall Alpha Preview

An experimental Debian 13 AMD64 package brings the existing administrative
workflow into separate systemd API, helper and namespace services. Management
uses an explicit LAN address/device and source prefix; enforcement remains in
three isolated laboratory namespaces. Installation does not activate host rules.

See the [runtime contract and validation status](packaging/preview/README.md) and
the [English](packaging/preview/docs/en.md),
[Español](packaging/preview/docs/es.md) and
[Português](packaging/preview/docs/pt.md) procedures. Native acceptance is pending;
the package is not a production firewall or a signed appliance updater.

## Transactional configuration experiment

The isolated configuration POC exercises Candidate, Running and Startup revisions,
validation, confirmed commits, recovery and an integrity-checked local journal.
Its engines simulate acknowledgments and failures; they never change traffic.
Web/CLI/API adapter labels exercise one authorization contract with trusted test
identities. They are not deployed management endpoints, an authentication system
or a working configuration UI. The existing API and official CLI remain unchanged.

Run on Linux without root, using a new directory on the Linux filesystem:

```bash
go test -race -count=1 ./internal/configpoc ./cmd/andeiva-config-poc
poc_parent=$(mktemp -d)
bash scripts/poc-config.sh "$poc_parent/results"
```

The runner keeps three measured scenarios and their disposable stores for inspection.
The [next nftables experiment proposal](internal/configpoc/NFTABLES_POC_PLAN.md)
defines laboratory isolation and acceptance criteria; no real adapter is implemented.
Results cover real file operations and simulated engines, not real firewall apply,
power loss, signed updates, HA or production capacity. This prototype does not select
the final database. See the [design and limitations](internal/configpoc/README.md)
and guides in [English](internal/configpoc/docs/en.md),
[Español](internal/configpoc/docs/es.md) and [Português](internal/configpoc/docs/pt.md).

## Container checks

With a running Docker engine:

```bash
docker build --target check-go -t andeiva-go-check .
docker build --target check-web -t andeiva-web-check .
docker compose config --quiet
docker compose up --build --wait --wait-timeout 60
docker compose exec -T andeiva-api /andeiva-api --healthcheck
docker compose exec -T andeiva-api /andeiva --lang es status
docker compose down --remove-orphans
```

Compose uses an internal network without publishing host ports. The probe runs
inside the container. For a localhost HTTP endpoint, use the native development
commands above. The container runs without root or Linux capabilities, uses a
read-only filesystem and has bounded process, memory and log limits. It does not
install host services or change host firewall settings directly.

See [CONTRIBUTING.md](CONTRIBUTING.md) for validation commands and EN/ES/PT notes.
GitHub workflows must run and repository review protections must be configured
before an integration can be accepted. Successful compilation alone does not
validate Debian/VMware compatibility, capacity or production security.

## Project documentation

The [authenticated firewall administration laboratory](internal/firewalladmin/README.md)
adds a shared Web, CLI and HTTPS API workflow for typed IPv4 TCP/UDP rules.
Its separate executor controls only disposable namespaces; it is not installed as
the appliance firewall. See the EN/ES/PT procedures and recorded limitations.

The [isolated nftables experiment](internal/nftpoc/README.md) connects the
transactional configuration engine to a bounded real kernel policy in three
laboratory namespaces. See its [validation and limitations](internal/nftpoc/VALIDATION.md)
and EN/ES/PT procedures. It does not expose firewall management in the product UI,
CLI or API and must not run as a privileged test on shared CI.

| Guide | Contents |
|---|---|
| [Contributing](CONTRIBUTING.md) | Development commands, tests and contribution scope |
| [Security policy](SECURITY.md) | Current limitations and private reporting requirements |
| [Code of conduct](CODE_OF_CONDUCT.md) | Standards for participation |
| [Changelog](CHANGELOG.md) | Unreleased source changes |

Bug reports, documentation improvements and focused changes are welcome once
public contributions open. Discuss significant changes before implementation and
include reproducible validation in each pull request. Security reports belong in
the private reporting process, not public issues.

## License

ANDEIVA's original code is licensed under the [Apache License 2.0](LICENSE).
See [NOTICE](NOTICE) for third-party attributions.

The ANDEIVA name and artwork do not imply registered trademark status.

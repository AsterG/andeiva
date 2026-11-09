# ANDEIVA Security Gateway

ANDEIVA is an ASTERG project in early development. This repository contains the
initial Go backend and CLI, a React/TypeScript development page, and validation
workflows. It does not yet implement a firewall, authentication, traffic inspection,
VPN, persistent configuration, an installer or an appliance update mechanism.

The intended appliance base is Debian 13. Container targets below are development
checks, not appliance images. Web, CLI and API functional parity is a requirement
for future management features; those features are not present in this scaffold.

## Source layout

| Path | Purpose |
|---|---|
| `cmd/andeiva` | CLI entry point |
| `cmd/andeiva-api` | Development liveness server |
| `internal/cli` | CLI parsing, localized output and tests |
| `internal/httpserver` | Bounded HTTP server, local probe and tests |
| `frontend` | React/TypeScript source, translations and tests |
| `scripts` | Repeatable source and build checks |
| `.github/workflows` | Quality and security checks; no publishing |

## Development

Use Go 1.27.3 and Node.js 24.20.0 with npm. Commands for Linux/WSL:

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

Original code: [Apache-2.0](LICENSE). Third-party components retain their licenses;
dependency inventories are not a substitute for redistribution review. The ANDEIVA
name and artwork do not imply registered trademark status.

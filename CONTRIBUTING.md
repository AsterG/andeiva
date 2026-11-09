# Development and validation

## English

This is a development scaffold. Keep changes small and include tests for new
behavior and rejected input. Do not add management features without their security
contracts. Never commit credentials, private operational material or local tooling.
Do not force-add ignored files. No release or deployment workflow is configured.

Install frontend dependencies from the committed lockfile, without lifecycle scripts:

```bash
npm --prefix frontend ci --ignore-scripts --no-audit --no-fund
bash scripts/check.sh
go test -race ./cmd/... ./internal/...
bash scripts/smoke-api.sh
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
go run github.com/securego/gosec/v2/cmd/gosec@v2.30.0 ./cmd/... ./internal/...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./cmd/... ./internal/...
go run github.com/zricethezav/gitleaks/v8@v8.30.1 git --redact --no-banner --log-opts=--all
npm --prefix frontend audit --audit-level=moderate
npm --prefix frontend sbom --sbom-format=cyclonedx
node scripts/check-licenses.mjs
```

Security tools and package installation require registry access on the development
machine. These commands do not configure online updates on an appliance. Secret
history scanning requires committed history; inspect prospective source separately
before the initial commit. Do not upload local planning directories as CI artifacts.

Run the Docker commands in the README with an available engine. Record the platform,
tool versions, commands, exit codes and any missing checks. A stopped Docker engine
is an unresolved execution gate, not a passing container test. Linux cross-compiles
are not tests on physical ARM hardware or a VMware appliance.

## Español

Base de desarrollo sin funciones de firewall ni administración. Usa los comandos
anteriores para instalar desde el lockfile y ejecutar calidad, pruebas, compilación,
seguridad e inventario. Ejecuta también las pruebas Docker del README. Registra
resultados reales y controles pendientes; compilar no demuestra compatibilidad con
Debian/VMware ni capacidad del appliance.

La API local responde en `/healthz`; es solo salud del proceso. La CLI admite
`go run ./cmd/andeiva --lang es status`. La página inicia en inglés y tema claro;
español, portugués y oscuro se eligen explícitamente. No hay usuarios ni sesiones.
Detén la API con Ctrl+C y Compose con `docker compose down --remove-orphans`.
No agregues archivos ignorados, secretos, instrucciones locales ni material privado.

## Português

Base de desenvolvimento sem funções de firewall ou administração. Use os comandos
acima para instalar pelo lockfile e executar qualidade, testes, compilação,
segurança e inventário. Execute também os testes Docker do README. Registre os
resultados reais e as verificações pendentes; compilar não comprova compatibilidade
com Debian/VMware nem capacidade do appliance.

A API local responde em `/healthz`; indica apenas a atividade do processo. A CLI
aceita `go run ./cmd/andeiva --lang pt status`. A página inicia em inglês e tema
claro; espanhol, português e escuro são escolhas explícitas. Não há usuários ou
sessões. Pare a API com Ctrl+C e Compose com `docker compose down --remove-orphans`.
Não inclua arquivos ignorados, segredos, instruções locais ou material privado.

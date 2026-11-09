#!/usr/bin/env bash
set -euo pipefail
node scripts/check-repository.mjs
bash scripts/check-go-format.sh
go vet ./cmd/... ./internal/...
go test ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build

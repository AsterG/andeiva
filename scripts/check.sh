#!/usr/bin/env bash
set -euo pipefail
go_test_flags=()
if [[ $# == 1 && $1 == --race ]]; then
  go_test_flags=(-race -timeout=20m)
elif (( $# != 0 )); then
  echo 'Usage: scripts/check.sh [--race]' >&2
  exit 2
fi
node scripts/check-repository.mjs
bash scripts/check-go-format.sh
go vet ./cmd/... ./internal/...
go test "${go_test_flags[@]}" ./cmd/... ./internal/...
go build ./cmd/... ./internal/...
npm --prefix frontend run lint
npm --prefix frontend test
npm --prefix frontend run build

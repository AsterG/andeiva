#!/usr/bin/env bash
set -euo pipefail
go_test_flags=()
exclude_configpoc=false
if [[ $# == 1 && $1 == --race ]]; then
  go_test_flags=(-race -timeout=20m)
elif [[ $# == 1 && $1 == --race-without-configpoc ]]; then
  go_test_flags=(-race -timeout=20m)
  exclude_configpoc=true
elif (( $# != 0 )); then
  echo 'Usage: scripts/check.sh [--race | --race-without-configpoc]' >&2
  exit 2
fi
node scripts/check-repository.mjs
bash scripts/check-go-format.sh
go vet ./cmd/... ./internal/...
if $exclude_configpoc; then
  packages=$(go list ./cmd/... ./internal/...)
  mapfile -t test_packages < <(printf '%s\n' "$packages" | grep -vxF github.com/AsterG/andeiva/internal/configpoc)
  go test "${go_test_flags[@]}" "${test_packages[@]}"
else
  go test "${go_test_flags[@]}" ./cmd/... ./internal/...
fi
go build ./cmd/... ./internal/...
npm --prefix frontend run lint
npm --prefix frontend test
npm --prefix frontend run build

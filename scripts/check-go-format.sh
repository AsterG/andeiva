#!/usr/bin/env bash
set -euo pipefail
unformatted=$(gofmt -l cmd internal)
if [[ -n "$unformatted" ]]; then
  printf '%s\n' "$unformatted"
  exit 1
fi

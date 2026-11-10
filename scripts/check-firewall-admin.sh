#!/usr/bin/env bash
set -euo pipefail
export GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOTELEMETRY=off

# Compilation only: shared CI never starts the privileged laboratory supervisor.
for target in linux windows darwin; do
  GOOS="$target" GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/andeiva-admin-lab ./cmd/andeiva
done

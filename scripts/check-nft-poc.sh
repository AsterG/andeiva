#!/usr/bin/env bash
set -euo pipefail
export GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOTELEMETRY=off

# No root, namespaces, capabilities or real firewall operations in shared CI.
go test -race -count=1 ./cmd/andeiva-nft-poc ./internal/nftguardian ./internal/nftpoc ./internal/nftfixture
for target in linux windows darwin; do
  GOOS="$target" GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/andeiva-nft-poc ./internal/nftpoc ./internal/nftguardian ./internal/nftfixture
done

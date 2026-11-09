#!/usr/bin/env bash
set -euo pipefail
export CGO_ENABLED=0 GOTOOLCHAIN=local GOWORK=off

# Cross-compilation verifies source selection, not appliance runtime support.
for target in linux windows darwin; do
  case "$target" in linux) selected=linux; excluded=other;; *) selected=other; excluded=linux;; esac
  for spec in 'cmd/andeiva-config-poc usage' 'internal/configpoc lock'; do
    read -r package base <<< "$spec"
    files=$(GOOS=$target GOARCH=amd64 go list -f '{{join .GoFiles " "}}' "./$package")
    ignored=$(GOOS=$target GOARCH=amd64 go list -f '{{join .IgnoredGoFiles " "}}' "./$package")
    [[ " $files " == *" ${base}_${selected}.go "* && " $files " != *" ${base}_${excluded}.go "* && " $ignored " == *" ${base}_${excluded}.go "* ]] || {
      printf 'Unexpected source selection: %s %s\n' "$target" "$package" >&2; exit 1;
    }
  done
  GOOS=$target GOARCH=amd64 go build ./internal/configpoc ./cmd/andeiva-config-poc
  printf 'PASS: %s/amd64 source selection and compilation\n' "$target"
done

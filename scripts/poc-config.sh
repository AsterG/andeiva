#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 1 || $1 != /* || $(uname -s) != Linux || $EUID == 0 ]]; then
  printf '%s\n' 'Usage (non-root Linux): bash scripts/poc-config.sh NEW_ABSOLUTE_OUTPUT_DIR' >&2
  exit 2
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
out=$1
case "$out" in
  /|*/|*//*|*/./*|*/../*|*/.|*/..)
    printf '%s\n' 'Output path must be canonical.' >&2; exit 2;;
esac
# Validate the original path before resolution can hide a symlink component.
parent=$(dirname -- "$out")
while :; do
  [[ -d $parent && ! -L $parent ]] || { printf '%s\n' 'Output parent must exist without symlinks.' >&2; exit 2; }
  [[ $parent != / ]] || break
  parent=$(dirname -- "$parent")
done
case "$out/" in "$repo/"*) printf '%s\n' 'Keep experiment output outside the source tree.' >&2; exit 2;; esac
[[ ! -e $out && ! -L $out ]] || { printf '%s\n' 'Output directory must be new.' >&2; exit 2; }
mkdir -m 700 -- "$out"
cd -- "$repo"
export GOENV=off GOWORK=off GOTOOLCHAIN=local GOTELEMETRY=off GOPROXY=off GOSUMDB=off
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$out/andeiva-config-poc" ./cmd/andeiva-config-poc
go version > "$out/toolchain.txt"
git rev-parse HEAD > "$out/source-revision.txt"
if [[ -z $(git status --porcelain --untracked-files=normal) ]]; then
  printf 'clean\n' > "$out/source-state.txt"
else
  printf 'working-tree\n' > "$out/source-state.txt"
fi
{
  printf '%s\0' go.mod scripts/poc-config.sh
  find cmd/andeiva-config-poc internal/configpoc -type f -name '*.go' -print0
} | sort -z | xargs -0 sha256sum > "$out/source-files.sha256"
"$out/andeiva-config-poc" -state-dir "$out/warmup" -iterations 1 > "$out/warmup.json"
for run in 1 2 3; do
  "$out/andeiva-config-poc" -state-dir "$out/state-$run" -iterations 20 > "$out/run-$run.json"
done
(
  cd -- "$out"
  sha256sum andeiva-config-poc warmup.json run-*.json toolchain.txt source-revision.txt source-state.txt source-files.sha256 > SHA256SUMS
)
printf 'PASS: three isolated simulator runs; reports in %s\n' "$out"

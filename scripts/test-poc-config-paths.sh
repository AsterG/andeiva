#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $(uname -s) == Linux && $EUID != 0 ]] || { printf 'Requires non-root Linux.\n' >&2; exit 2; }
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir -- "$scratch/real"
ln -s -- "$scratch/real" "$scratch/link"
for out in "$scratch/./new" "$scratch//new" "$scratch/real/../new" "$scratch/new/" "$scratch/link/new" "$scratch/missing/../new" "$scratch/missing/new" "$repo/poc-path-test-output"; do
  code=0
  bash "$repo/scripts/poc-config.sh" "$out" > "$scratch/output" 2>&1 || code=$?
  [[ $code == 2 ]] || { cat "$scratch/output" >&2; printf 'Unexpected exit: %s\n' "$code" >&2; exit 1; }
  [[ ! -e $scratch/new && ! -e $scratch/real/new && ! -e $scratch/missing && ! -e $repo/poc-path-test-output ]] || { printf 'Rejected path created output.\n' >&2; exit 1; }
done
printf 'PASS: output path validation has no directory side effects.\n'

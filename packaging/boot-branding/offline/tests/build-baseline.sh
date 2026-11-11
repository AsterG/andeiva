#!/usr/bin/env bash
# DEV only: prove invalid public baseline fixtures fail before APT resolution.
set -euo pipefail
umask 077
(( EUID != 0 && $# == 1 )) || exit 1
products=$(realpath -e "$1")
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scratch=$(mktemp -d /tmp/andeiva-build-baseline.XXXXXXXX)
cleanup() {
  case "$scratch" in /tmp/andeiva-build-baseline.*) rm -rf -- "$scratch" ;; *) exit 1 ;; esac
}
trap cleanup EXIT
failure() {
  if [[ -n ${mode:-} && -f "$scratch/$mode/result.log" ]]; then head -c 2048 "$scratch/$mode/result.log" >&2; fi
}
trap failure ERR
for mode in missing changed; do
  mkdir "$scratch/$mode"
  status="$scratch/$mode/status"
  if [[ "$mode" = missing ]]; then
    : > "$status"
  else
    awk -F '\t' '$1 == "baseline" { printf "Package: %s\nStatus: install ok installed\nVersion: %s\nArchitecture: %s\n\n", $2, $3, $4 }' "$source_dir/check/profile.go" | sed 's/2.12-9+deb13u2/2.12-9+deb13u3/g' > "$status"
  fi
  if timeout --kill-after=5s 60s bash "$source_dir/build.sh" "$status" "$products" "$scratch/$mode/output" 1794355200 > "$scratch/$mode/result.log" 2>&1; then
    printf 'Invalid baseline accepted: %s\n' "$mode" >&2
    exit 1
  fi
  grep -qx ANDEIVA_OFFLINE_BASELINE_REQUIRED "$scratch/$mode/result.log"
  if grep -q ANDEIVA_OFFLINE_AUTHENTICATED_UPDATE_FAILED "$scratch/$mode/result.log"; then exit 1; fi
  [[ -z $(find "$scratch/$mode/output" -maxdepth 1 -name '*.tar.gz' -print -quit) ]]
done
printf 'DEV builder baseline missing/changed refused before APT\n'

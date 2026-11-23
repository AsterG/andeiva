#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || ! $1 =~ ^[0-9]$ || ! $2 =~ ^[1-9]$ ]] || (( $1 >= $2 )); then
  echo 'Usage: scripts/check-configpoc-race.sh <zero-based-shard> <shard-count>' >&2
  exit 2
fi

package=./internal/configpoc
# Discover entries under the same build and race settings as the test run.
listed=$(go test -race "$package" -list '^(Test|Example|Fuzz)')
mapfile -t selected < <(printf '%s\n' "$listed" |
  awk -v shard="$1" -v total="$2" '/^(Test|Example|Fuzz)[[:alnum:]_]+$/ {
    if (index_in_suite++ % total == shard) print
  }')
if (( ${#selected[@]} == 0 )); then
  echo 'No configpoc tests in this shard' >&2
  exit 1
fi
pattern=$(IFS='|'; printf '%s' "${selected[*]}")
printf 'Running configpoc race shard %d of %d (%d entries)\n' "$(($1 + 1))" "$2" "${#selected[@]}"
go test -race -count=1 -timeout=20m "$package" -run "^($pattern)$"

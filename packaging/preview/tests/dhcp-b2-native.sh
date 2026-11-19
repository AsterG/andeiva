#!/usr/bin/env bash
set -euo pipefail

validate_b2_log() {
  local profile=$1 log=$2 expected count size
  [[ $profile == 70 || $profile == 71 ]] || return 1
  [[ -f $log && ! -L $log ]] || return 1
  size=$(stat -c '%s' -- "$log") || return 1
  (( size > 0 && size <= 2097152 )) || return 1
  expected="TestNativeRoutedDHCPB2Natural${profile}V4"
  for pattern in "^=== RUN   ${expected}$" "^--- PASS: ${expected} \([0-9]+([.][0-9]+)?s\)$" '^=== RUN   ' '^--- PASS: ' '^PASS$' 'ANDEIVA_NATIVE_DHCP_B2_RESULT_V4 ' '^ANDEIVA_NATIVE_DHCP_JOBS_CLEANUP_OK$'; do
    count=$(grep -Ec -- "$pattern" "$log") || return 1
    [[ $count == 1 ]] || return 1
  done
  # Fixed encoder puts top-level lease first; another profile cannot qualify.
  count=$(grep -Ec -- "ANDEIVA_NATIVE_DHCP_B2_RESULT_V4 \{\"lease_seconds\":${profile}," "$log") || return 1
  [[ $count == 1 ]] || return 1
  # Revision 2 cannot be satisfied by the old 120-second shortening trial.
  grep -Eq -- "ANDEIVA_NATIVE_DHCP_B2_RESULT_V4 .*\"lease_seconds\":${profile},\"fixture_version\":2,\"initial_lease_seconds\":71,\"natural_renewals\":1,\"source_continuity\":true," "$log" || return 1
  # Reject older B2 binaries whose result predates the strict WAIT oracle.
  grep -Eq -- 'ANDEIVA_NATIVE_DHCP_B2_RESULT_V4 .*"internal_margin_diagnostic_transitions":1,"wait_closed_proof":\{' "$log" || return 1
  grep -Eq -- 'ANDEIVA_NATIVE_DHCP_B2_RESULT_V4 .*"wait_traffic_oracle":\{"writes_fully_inside_wait":[1-9][0-9]*,"sink_receipts_of_fully_bounded_writes":0,' "$log" || return 1
  if grep -Eq -- '^[[:space:]]*--- (SKIP|FAIL):|^[[:space:]]*SKIP$|^FAIL([[:space:]]|$)|no tests to run' "$log"; then
    return 1
  else
    [[ $? == 1 ]] || return 1
  fi
}

# Pure read-only regression entry: no privileges, namespaces or engine required.
if [[ $# == 3 && $1 == --check-log ]]; then
  validate_b2_log "$2" "$3"
  exit $?
fi
if [[ $# != 4 || $1 != --isolated-lab || ${EUID} != 0 || -n ${CI:-} ]]; then exit 64; fi
case $4 in
  --lease-70) profile=70 ;;
  --lease-71) profile=71 ;;
  *) exit 64 ;;
esac
[[ ! -L $0 && -f $0 && $(stat -c '%u:%h' -- "$0") == 0:1 ]]
mode=$(stat -c '%a' -- "$0")
(( (8#$mode & 0022) == 0 ))
directory=$(cd -- "$(dirname -- "$0")" && pwd -P)
ancestor=$directory
while :; do
  [[ ! -L $ancestor && -d $ancestor && $(stat -c '%u' -- "$ancestor") == 0 ]]
  mode=$(stat -c '%a' -- "$ancestor")
  (( (8#$mode & 0022) == 0 ))
  [[ $ancestor == / ]] && break
  ancestor=$(dirname -- "$ancestor")
done
driver="$directory/dhcp-jobs-native.sh"
[[ ! -L $driver && -f $driver && $(stat -c '%u:%h' -- "$driver") == 0:1 ]]
mode=$(stat -c '%a' -- "$driver")
(( (8#$mode & 0022) == 0 ))
umask 077
capture=$(mktemp -d /run/andeiva-b2-log.XXXXXXXX)
trap 'rm -f -- "$capture/output.log"; rmdir -- "$capture"' EXIT
log="$capture/output.log"
# Reuse reviewed namespace/cleanup logic with a dedicated exact B2 test name.
# Bound capture without imposing file-size rlimits on product children.
if /usr/bin/timeout --kill-after=2s 235s /usr/bin/bash "$driver" --isolated-lab "$2" "$3" "--b2-${profile}" 2>&1 | head -c 2097153 | tee -- "$log"; then
  validate_b2_log "$profile" "$log"
else
  exit 1
fi

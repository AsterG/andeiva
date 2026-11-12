#!/usr/bin/env bash
# Unprivileged regression for the existing harness log gate; no mounts or privileged operations.
set -Eeuo pipefail
umask 077
task_source=$(dirname -- "${BASH_SOURCE[0]}")/storage-pressure.sh
source <(sed -n '/^verify_test_log() {$/,/^}$/p; /^capture_test_output() {$/,/^}$/p' "$task_source")
declare -F verify_test_log >/dev/null
task_base=$(mktemp -d "${TMPDIR:-/tmp}/andeiva-storage-log-test.XXXXXXXX")
cleanup() {
  local task_status=$?
  trap - EXIT
  rm -f -- "$task_base/output.log" "$task_base/runner-write.bin" || task_status=1
  rmdir -- "$task_base" || task_status=1
  exit "$task_status"
}
trap cleanup EXIT
fake_runner() { printf 'testing: warning: no tests to run\nPASS\n'; return 0; }
fake_runner | tee "$task_base/output.log" >/dev/null
if verify_test_log "$task_base/output.log" TestNativeVolumePressure bytes; then exit 1; fi
if verify_test_log "$task_base/output.log" TestRealStoragePressure; then exit 1; fi
printf '=== RUN   TestNativeVolumePressure\n--- PASS: TestNativeVolumePressure (0.12s)\n' > "$task_base/output.log"
if verify_test_log "$task_base/output.log" TestNativeVolumePressure bytes; then exit 1; fi
printf 'ANDEIVA_NATIVE_VOLUME_CASE_PASS=bytes\n' >> "$task_base/output.log"
verify_test_log "$task_base/output.log" TestNativeVolumePressure bytes
if verify_test_log "$task_base/output.log" TestNativeVolumePressure inodes; then exit 1; fi
printf '=== RUN   TestRealStoragePressure\n--- PASS: TestRealStoragePressure (0.12s)\n' > "$task_base/output.log"
verify_test_log "$task_base/output.log" TestRealStoragePressure
printf '%s\n' '--- SKIP: TestRealStoragePressure (0.00s)' > "$task_base/output.log"
if verify_test_log "$task_base/output.log" TestRealStoragePressure; then exit 1; fi
printf 'ANDEIVA_STORAGE_LOG_GATE_RESULT=pass\n'

# The runner must exceed the log cap to exercise real ENOSPC. Only tee inherits
# RLIMIT_FSIZE; inheriting it in the runner would qualify EFBIG by mistake.
capture_test_output "$task_base/output.log" /bin/bash -c 'set -euo pipefail; dd if=/dev/zero of="$1" bs=2097152 count=1 status=none; printf "runner-write-complete\n"' _ "$task_base/runner-write.bin" >/dev/null
[[ $(stat -c '%s' "$task_base/runner-write.bin") = 2097152 ]]
rm -- "$task_base/runner-write.bin"
printf 'ANDEIVA_STORAGE_RUNNER_LIMIT_SCOPE_RESULT=pass\n'

# Pinned Go emits seconds; accept anchored composite durations for compatible producers.
for task_duration in 0.12s 120.00s 1m2.34s 1h2m3.4s; do
 printf '=== RUN   TestNativeVolumePressure\n--- PASS: TestNativeVolumePressure (%s)\nANDEIVA_NATIVE_VOLUME_CASE_PASS=bytes\n' "$task_duration" > "$task_base/output.log"
 verify_test_log "$task_base/output.log" TestNativeVolumePressure bytes
done
for task_duration in -1s 1m 1h BAD 1s-junk; do
 printf '=== RUN   TestNativeVolumePressure\n--- PASS: TestNativeVolumePressure (%s)\nANDEIVA_NATIVE_VOLUME_CASE_PASS=bytes\n' "$task_duration" > "$task_base/output.log"
 if verify_test_log "$task_base/output.log" TestNativeVolumePressure bytes; then exit 1; fi
done
printf 'ANDEIVA_STORAGE_DURATION_GATE_RESULT=pass\n'

# The EXIT trap is idempotent and preserves an original failure before any log exists.
task_cleanup_source=$(sed -n '/^cleanup() {$/,/^}$/p' "${BASH_SOURCE[0]}")
for task_original_status in 0 7; do
 task_cleanup_base=$(mktemp -d "${TMPDIR:-/tmp}/andeiva-storage-cleanup-test.XXXXXXXX")
 if /bin/bash -c 'set -Eeuo pipefail; task_base=$1; eval "$2"; trap cleanup EXIT; exit "$3"' _ "$task_cleanup_base" "$task_cleanup_source" "$task_original_status"; then
  task_observed_status=0
 else
  task_observed_status=$?
 fi
 [[ $task_observed_status = "$task_original_status" && ! -e $task_cleanup_base ]]
done
printf 'ANDEIVA_STORAGE_CLEANUP_GATE_RESULT=pass\n'

# Malicious inherited environment cannot select copied-volume mode in the old CLI.
source <(sed -n '/^parse_volume_arguments() {$/,/^}$/p' "$task_source")
export ANDEIVA_STORAGE_VOLUME_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export ANDEIVA_STORAGE_INSPECTOR=/untrusted/inspector
export ANDEIVA_STORAGE_INSPECTOR_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
parse_volume_arguments --authorized-debian-lab /trusted/test.test expected --isolated-storage-only
[[ -z $task_volume_id && -z $task_inspector_input && -z $task_inspector_sha ]]
[[ ! -v ANDEIVA_STORAGE_VOLUME_ID && ! -v ANDEIVA_STORAGE_INSPECTOR && ! -v ANDEIVA_STORAGE_INSPECTOR_SHA ]]
[[ ${#task_volume_arguments[@]} = 4 && ${task_volume_arguments[0]} = --authorized-debian-lab ]]
for task_volume_mode in --authorized-debian-volumes --inside-volumes; do
 parse_volume_arguments "$task_volume_mode" /trusted/test.test expected namespace /trusted/inspector digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 [[ $task_volume_id = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa && $task_inspector_input = /trusted/inspector && $task_inspector_sha = digest ]]
 [[ ${#task_volume_arguments[@]} = 4 ]]
 if [[ $task_volume_mode = --inside-volumes ]]; then
  [[ ${task_volume_arguments[0]} = --inside ]]
 else
  [[ ${task_volume_arguments[0]} = --authorized-debian-lab ]]
 fi
done
parse_volume_arguments --authorized-debian-lab /trusted/test.test expected --isolated-storage-only
[[ -z $task_volume_id && -z $task_inspector_input && -z $task_inspector_sha ]]
printf 'ANDEIVA_STORAGE_ENVIRONMENT_MODE_GATE_RESULT=pass\n'

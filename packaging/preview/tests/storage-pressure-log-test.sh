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

# A failed worker must return from its FD-scoped function before EXIT cleanup.
# Otherwise Bash retains the directory capability while the trap unmounts it.
task_capture_source=$(declare -f capture_test_output)
if /bin/bash -c '
 set -Eeuo pipefail
 exec 3<&- 4<&-
 eval "$3"
 trap '\''if [[ -e /proc/self/fd/3 || -e /proc/self/fd/4 ]]; then exit 91; fi'\'' EXIT
 if ! capture_test_output "$2" /bin/false 3<"$1" 4<"$2"; then exit 7; fi
 exit 92
' _ "$task_base" "$task_base/output.log" "$task_capture_source"; then
 exit 1
else
 [[ $? = 7 ]]
fi
printf 'ANDEIVA_STORAGE_WORKER_FD_CLEANUP_GATE_RESULT=pass\n'

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

# V2 is an explicit argv mode, never an inherited variable or legacy selection.
export task_v2=1
parse_volume_arguments --authorized-debian-lab /trusted/test.test expected --isolated-storage-only
[[ $task_v2 = 0 ]]
for task_volume_mode in --authorized-debian-v2-volumes --inside-v2-volumes; do
 parse_volume_arguments "$task_volume_mode" /trusted/test.test expected namespace /trusted/inspector digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 [[ $task_v2 = 1 && $task_volume_id = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa && ${#task_volume_arguments[@]} = 4 ]]
done
parse_volume_arguments --authorized-debian-v2-volumes /trusted/test.test expected namespace /trusted/inspector digest
[[ $task_v2 = 0 && -z $task_volume_id && ${#task_volume_arguments[@]} = 6 ]]
for task_volume_mode in --authorized-debian-v2-reserve-volumes --inside-v2-reserve-volumes; do
 parse_volume_arguments "$task_volume_mode" /trusted/test.test expected namespace /trusted/inspector digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 [[ $task_v2 = 1 && $task_reserves = 1 && $task_volume_id = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa && ${#task_volume_arguments[@]} = 4 ]]
 if [[ $task_volume_mode = --inside-v2-reserve-volumes ]]; then
  [[ ${task_volume_arguments[0]} = --inside ]]
 else
  [[ ${task_volume_arguments[0]} = --authorized-debian-lab ]]
 fi
done
export task_reserves=1
parse_volume_arguments --authorized-debian-v2-volumes /trusted/test.test expected namespace /trusted/inspector digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[[ $task_v2 = 1 && $task_reserves = 0 ]]
parse_volume_arguments --authorized-debian-v2-reserve-volumes /trusted/test.test expected namespace /trusted/inspector digest
[[ $task_v2 = 0 && $task_reserves = 0 && -z $task_volume_id && ${#task_volume_arguments[@]} = 6 ]]
for task_case in bytes inodes open-deleted; do
 printf '=== RUN   TestNativeV2VolumePressure\n--- PASS: TestNativeV2VolumePressure (1.01s)\nANDEIVA_NATIVE_V2_CASE_PASS=%s\n' "$task_case" > "$task_base/output.log"
 verify_test_log "$task_base/output.log" TestNativeV2VolumePressure "$task_case"
 if verify_test_log "$task_base/output.log" TestNativeV2VolumePressure readonly; then exit 1; fi
 if verify_test_log "$task_base/output.log" TestNativeVolumePressure "$task_case"; then exit 1; fi
done
for task_result in 'testing: warning: no tests to run' '--- SKIP: TestNativeV2VolumePressure (0.00s)' '--- FAIL: TestNativeV2VolumePressure (0.00s)'; do
 printf '%s\nPASS\nANDEIVA_NATIVE_V2_CASE_PASS=bytes\n' "$task_result" > "$task_base/output.log"
 if verify_test_log "$task_base/output.log" TestNativeV2VolumePressure bytes; then exit 1; fi
done
source <(sed -n '/^verify_v2_sentinel_snapshot() {$/,/^}$/p' "$task_source")
task_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
verify_v2_sentinel_snapshot "$task_hash" 1:2:3 0:0:700 0:0:600:1 "$task_hash" 1:2:3
for task_invalid in 1 2 3 4 5 6; do
 task_args=("$task_hash" 1:2:3 0:0:700 0:0:600:1 "$task_hash" 1:2:3)
 task_args[task_invalid-1]=invalid
 if verify_v2_sentinel_snapshot "${task_args[@]}"; then exit 1; fi
done
printf 'ANDEIVA_STORAGE_V2_MODE_LOG_SENTINEL_GATE_RESULT=pass\n'

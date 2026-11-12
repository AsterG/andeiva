#!/usr/bin/env bash
# Unprivileged regression for the existing harness log gate; no mounts or privileged operations.
set -Eeuo pipefail
umask 077
task_source=$(dirname -- "${BASH_SOURCE[0]}")/storage-pressure.sh
source <(sed -n '/^verify_test_log() {$/,/^}$/p; /^capture_test_output() {$/,/^}$/p' "$task_source")
declare -F verify_test_log >/dev/null
task_base=$(mktemp -d "${TMPDIR:-/tmp}/andeiva-storage-log-test.XXXXXXXX")
cleanup() { rm -- "$task_base/output.log"; rmdir -- "$task_base"; }
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

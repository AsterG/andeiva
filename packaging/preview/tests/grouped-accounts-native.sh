#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || $1 != --isolated-accounts-lab || ${EUID} != 0 || -n ${CI:-} ]]; then
  printf '%s\n' 'Use --isolated-accounts-lab TEST_BINARY only in an authorized root Debian laboratory.' >&2
  exit 2
fi
grep -qx 'ID=debian' /etc/os-release
grep -qx 'VERSION_ID="13"' /etc/os-release
[[ -f $2 && ! -L $2 && -x $2 ]]
fixture=$(realpath -e -- "$2")
[[ $(stat -c '%u:%h' -- "$fixture") == 0:1 ]]
[[ $(stat -c '%u:%a' -- "$(dirname -- "$fixture")") == 0:755 ]]
mode=$(stat -c '%a' -- "$fixture")
(( (8#$mode & 0022) == 0 ))
# The test makes this new mount namespace private before mounting its tmpfs.
umask 077
work=$(mktemp -d /tmp/andeiva-accounts-proof.XXXXXXXX)
log="$work/observations.log"
cleanup() { rm -f -- "$log"; rmdir -- "$work"; }
trap cleanup EXIT
status=0
(
  ulimit -f 1024
  exec /usr/bin/unshare --mount -- /usr/bin/timeout --kill-after=2s 35s \
    "$fixture" -test.run '^TestRoutedAccountsNativeV3$' -test.count=1 \
    -test.timeout=30s -test.v -andeiva-native-accounts-v3
) > "$log" 2>&1 || status=$?
cat -- "$log"
if (( status != 0 )); then exit "$status"; fi
[[ $(grep -Ec '^--- PASS: TestRoutedAccountsNativeV3 \([^()]+\)$' "$log") == 1 ]]
! grep -Eq '^--- (FAIL|SKIP):|^FAIL|no tests to run' "$log"
grep -Fxq PASS "$log"

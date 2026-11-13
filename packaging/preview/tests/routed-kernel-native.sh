#!/usr/bin/env bash
set -euo pipefail

# Root laboratory harness only; no interfaces or routes of the parent are changed.
if [[ $# != 2 || $1 != --isolated-lab || ${EUID} != 0 || -n ${CI:-} ]]; then
  printf '%s\n' 'Use --isolated-lab TEST_BINARY only in an authorized root laboratory.' >&2
  exit 2
fi
grep -qx 'ID=debian' /etc/os-release
grep -qx 'VERSION_ID="13"' /etc/os-release
[[ ! -L $2 && -f $2 ]]
fixture=$(realpath -e -- "$2")
parent=$(dirname -- "$fixture")
[[ $(stat -c '%u:%h' -- "$fixture") == 0:1 ]]
[[ $(stat -c '%u:%a' -- "$parent") == 0:700 ]]
mode=$(stat -c '%a' -- "$fixture")
(( (8#$mode & 0022) == 0 ))
[[ -x $fixture ]]
nonce=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
[[ $nonce =~ ^[a-f0-9]{12}$ ]]
declare -A owned=()
cleanup() {
  original=$?
  trap - EXIT INT TERM
  exec 3<&- 4<&- 5<&-
  cleanup_failed=0
  for suffix in g s w; do
    item="andkv3-${nonce}-${suffix}"
    if [[ -n ${owned[$item]:-} && -e /run/netns/$item ]]; then
      actual=$(stat -Lc '%i' -- "/run/netns/$item") || actual=unknown
      if [[ $actual == "${owned[$item]}" ]]; then
        /usr/bin/ip netns delete "$item" || cleanup_failed=1
      else
        printf '%s\n' 'Refusing cleanup after namespace identity changed.' >&2
        cleanup_failed=1
      fi
    fi
  done
  if (( original == 0 && cleanup_failed != 0 )); then original=1; fi
  if (( original == 0 )); then printf '%s\n' 'ANDEIVA_NATIVE_KERNEL_CLEANUP_OK'; fi
  exit "$original"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for suffix in s g w; do
  item="andkv3-${nonce}-${suffix}"
  [[ ! -e /run/netns/$item && ! -L /run/netns/$item ]]
  /usr/bin/ip netns add "$item"
  owned[$item]=$(stat -Lc '%i' -- "/run/netns/$item")
done
sha256sum -- "$fixture"
exec 3</proc/self/ns/net
exec 4<"/run/netns/andkv3-${nonce}-s"
exec 5<"/run/netns/andkv3-${nonce}-w"
ANDEIVA_NATIVE_KERNEL_V3=1 /usr/bin/timeout --kill-after=2s 45s \
  /usr/bin/ip netns exec "andkv3-${nonce}-g" "$fixture" \
  -test.run '^TestNativeRoutedKernelV3$' -test.count=1 -test.timeout=35s -test.v

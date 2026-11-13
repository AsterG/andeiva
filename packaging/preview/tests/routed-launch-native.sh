#!/usr/bin/env bash
set -euo pipefail

# Explicit root laboratory harness. Run inside a private mount namespace with
# a private /run/netns mount and a supervisor-owned process cgroup.
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
[[ $(stat -c '%u:%a' -- "$parent") == 0:755 ]]
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
  failed=0
  for suffix in g s w; do
    item="andlv3-${nonce}-${suffix}"
    if [[ -n ${owned[$item]:-} && -e /run/netns/$item ]]; then
      actual=$(stat -Lc '%i' -- "/run/netns/$item") || actual=unknown
      if [[ $actual != "${owned[$item]}" ]]; then
        printf '%s\n' 'Refusing cleanup after namespace identity changed.' >&2
        failed=1
        continue
      fi
      if ! pids=$(/usr/bin/ip netns pids "$item"); then
        printf '%s\n' 'Unable to verify namespace process absence; preserving its pin.' >&2
        failed=1
        continue
      fi
      if [[ -n $pids ]]; then
        printf '%s\n' 'Namespace still has processes; containing cgroup cleanup is required.' >&2
        failed=1
        continue
      fi
      /usr/bin/ip netns delete "$item" || failed=1
    fi
  done
  if (( original == 0 && failed != 0 )); then original=1; fi
  if (( original == 0 )); then printf '%s\n' 'ANDEIVA_NATIVE_LAUNCH_CLEANUP_OK'; fi
  exit "$original"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for suffix in s g w; do
  item="andlv3-${nonce}-${suffix}"
  [[ ! -e /run/netns/$item && ! -L /run/netns/$item ]]
  /usr/bin/ip netns add "$item"
  owned[$item]=$(stat -Lc '%i' -- "/run/netns/$item")
done
# Physical observations require two supported, active L2 links. Each peer stays
# inside a disposable namespace, without IPv4 addresses or external connectivity.
/usr/bin/ip -n "andlv3-${nonce}-g" link add lan0 address 02:00:00:00:01:01 type veth peer name source0
/usr/bin/ip -n "andlv3-${nonce}-g" link set source0 netns "andlv3-${nonce}-s"
/usr/bin/ip -n "andlv3-${nonce}-g" link add wan0 address 02:00:00:00:02:01 type veth peer name sink0
/usr/bin/ip -n "andlv3-${nonce}-g" link set sink0 netns "andlv3-${nonce}-w"
/usr/bin/ip -n "andlv3-${nonce}-s" link set source0 up
/usr/bin/ip -n "andlv3-${nonce}-w" link set sink0 up
/usr/bin/ip -n "andlv3-${nonce}-g" link set lan0 up
/usr/bin/ip -n "andlv3-${nonce}-g" link set wan0 up
sha256sum -- "$fixture"
exec 3<"/run/netns/andlv3-${nonce}-g"
exec 4<"/run/netns/andlv3-${nonce}-s"
exec 5<"/run/netns/andlv3-${nonce}-w"
ANDEIVA_NATIVE_LAUNCH_V3=1 /usr/bin/timeout --kill-after=2s 105s \
  "$fixture" -test.run '^TestNativeRoutedLaunchV3$' -test.count=1 -test.timeout=100s -test.v

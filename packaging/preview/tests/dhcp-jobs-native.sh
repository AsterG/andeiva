#!/usr/bin/env bash
set -euo pipefail

# Root laboratory only; the orchestrator supplies this exact dedicated unit and
# a private mount namespace. Never replace an installed/running appliance unit.
if [[ $# != 3 || $1 != --isolated-lab || ${EUID} != 0 || -n ${CI:-} ]]; then exit 64; fi
if [[ -e /proc/sys/fs/binfmt_misc/WSLInterop || $(uname -r) == *[Mm]icrosoft* ]]; then exit 64; fi
grep -qx 'ID=debian' /etc/os-release
grep -qx 'VERSION_ID="13"' /etc/os-release
grep -qx '0::/system.slice/andeiva-preview-grouped.service' /proc/self/cgroup
[[ $(stat -Lc '%i' /proc/self/ns/mnt) != $(stat -Lc '%i' /proc/1/ns/mnt) ]]
[[ -x /usr/sbin/dhcpcd && -x /usr/bin/busybox ]]
/usr/bin/busybox --list | grep -qx udhcpd
for artifact in "$0" "$2" "$3"; do
  [[ ! -L $artifact && -f $artifact && $(stat -c '%u:%h' -- "$artifact") == 0:1 ]]
  mode=$(stat -c '%a' -- "$artifact")
  (( (8#$mode & 0022) == 0 ))
done
fixture=$(realpath -e -- "$2")
hook=$(realpath -e -- "$3")
parent=$(dirname -- "$fixture")
[[ $(stat -c '%u:%a' -- "$parent") == 0:755 && -x $fixture && -x $hook ]]
# Keep source outside the hidden target; never install into the host filesystem.
[[ $hook != /usr/libexec/* ]]
for target in /run/netns /usr/libexec; do
  [[ -d $target && ! -L $target && $(stat -c '%u' -- "$target") == 0 ]]
done
/usr/bin/mount --make-rprivate /
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run/netns
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /usr/libexec
/usr/bin/install -m 0555 -- "$hook" /usr/libexec/andeiva-dhcp-hook
sha256sum -- "$hook" /usr/libexec/andeiva-dhcp-hook
nonce=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
[[ $nonce =~ ^[a-f0-9]{12}$ ]]
declare -A owned=()
cleanup() {
  original=$?
  trap - EXIT INT TERM
  exec 3<&- 4<&- 5<&-
  failed=0
  for suffix in g s w; do
    item="anddh4-${nonce}-${suffix}"
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
  if (( original == 0 )); then printf '%s\n' 'ANDEIVA_NATIVE_DHCP_JOBS_CLEANUP_OK'; fi
  exit "$original"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for suffix in s g w; do
  item="anddh4-${nonce}-${suffix}"
  [[ ! -e /run/netns/$item && ! -L /run/netns/$item ]]
  /usr/bin/ip netns add "$item"
  owned[$item]=$(stat -Lc '%i' -- "/run/netns/$item")
done
# Physical observations require two supported, active L2 links. Each peer stays
# inside a disposable namespace, without IPv4 addresses or external connectivity.
/usr/bin/ip -n "anddh4-${nonce}-g" link add lan0 address 02:00:00:00:01:01 type veth peer name source0
/usr/bin/ip -n "anddh4-${nonce}-g" link set source0 netns "anddh4-${nonce}-s"
/usr/bin/ip -n "anddh4-${nonce}-g" link add wan0 address 02:00:00:00:02:01 type veth peer name sink0
/usr/bin/ip -n "anddh4-${nonce}-g" link set sink0 netns "anddh4-${nonce}-w"
/usr/bin/ip -n "anddh4-${nonce}-s" link set source0 up
/usr/bin/ip -n "anddh4-${nonce}-w" link set sink0 up
/usr/bin/ip -n "anddh4-${nonce}-g" link set lan0 up
/usr/bin/ip -n "anddh4-${nonce}-g" link set wan0 up
/usr/bin/ip -n "anddh4-${nonce}-w" address add 198.18.1.1/24 dev sink0
sha256sum -- "$fixture"
exec 3<"/run/netns/anddh4-${nonce}-g"
exec 4<"/run/netns/anddh4-${nonce}-s"
exec 5<"/run/netns/anddh4-${nonce}-w"
ANDEIVA_NATIVE_DHCP_JOBS_V4=1 /usr/bin/timeout --kill-after=2s 225s \
  "$fixture" -test.run '^TestNativeRoutedDHCPJobsV4$' -test.count=1 -test.timeout=220s -test.v

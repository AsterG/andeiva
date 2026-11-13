#!/bin/bash
# Authorized disposable Debian 13 only. This never adopts physical host links.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077
[[ $EUID == 0 && ${ANDEIVA_ROUTED_LINKS_LAB_AUTHORIZED:-} == 1 && -z ${CI:-} ]]
[[ ! -e /proc/sys/fs/binfmt_misc/WSLInterop && $(uname -r) != *[Mm]icrosoft* ]]
grep -qx 'ID=debian' /etc/os-release
grep -qx 'VERSION_ID="13"' /etc/os-release
for file in "$0" ./routed-links-native.test; do
  [[ -f $file && ! -L $file && $(stat -c '%u:%h' "$file") == 0:1 ]]
  mode=$(stat -c '%a' "$file")
  [[ $mode =~ ^[0-7]{3,4}$ ]]
  (( (8#$mode & 0022) == 0 ))
done
if [[ $# == 0 ]]; then
  [[ -x ./routed-links-native.test ]]
  exec 3</proc/self/ns/net
  exec 4</proc/self/ns/mnt
  exec 6</proc/self/ns/pid
  exec unshare --mount --net --pid --fork -- /bin/bash "$0" isolated
fi
[[ $# == 1 && $1 == isolated ]]
# Validate origin pins before any mount. At this point /proc still sees host PID1.
for pair in '3 net' '4 mnt' '6 pid'; do
  read -r fd kind <<< "$pair"
  [[ $(readlink "/proc/self/fd/$fd") =~ ^$kind:\[[0-9]+\]$ ]]
  original=$(stat -Lc '%d:%i' "/proc/self/fd/$fd")
  current=$(stat -Lc '%d:%i' "/proc/self/ns/$kind")
  [[ $original == "$(stat -Lc '%d:%i' "/proc/1/ns/$kind")" ]]
  [[ $current != "$original" && $current == "$(stat -Lc '%d:%i' "/proc/thread-self/ns/$kind")" ]]
done
mount --make-rprivate /
mount -t proc -o nosuid,nodev,noexec proc /proc
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
mkdir -m 0755 /run/netns
for family in ipv4 ipv6; do
  for scope in all default; do printf '0\n' > "/proc/sys/net/$family/conf/$scope/forwarding"; done
done
printf '1\n' > /proc/sys/net/ipv6/conf/all/disable_ipv6
printf '1\n' > /proc/sys/net/ipv6/conf/default/disable_ipv6
ip link add lan-parent address 02:11:22:33:44:55 type dummy
ip link add wan-parent address 02:11:22:33:44:56 type dummy
ip link set lan-parent up
ip link set wan-parent up
mkdir -m 0700 /run/andeiva-routed-namespace
trap 'exit 130' INT
trap 'exit 143' TERM
exec 3</proc/self/ns/net
exec 4</run/andeiva-routed-namespace
exec 6<&-
if ANDEIVA_ROUTED_LINKS_NATIVE=1 ./routed-links-native.test -test.run '^TestRoutedGatewayLinksV3Native$|^TestRoutedRetirementSlotV3Native$' -test.v -test.timeout 45s > /run/andeiva-routed-result.log 2>&1; then
  cat /run/andeiva-routed-result.log
else
  failed=$?
  cat /run/andeiva-routed-result.log
  exit "$failed"
fi
[[ $(grep -c '^--- PASS: TestRoutedGatewayLinksV3Native ' /run/andeiva-routed-result.log) == 1 ]]
[[ $(grep -c '^--- PASS: TestRoutedRetirementSlotV3Native ' /run/andeiva-routed-result.log) == 1 ]]
! grep -Eq '^--- (FAIL|SKIP):|^FAIL' /run/andeiva-routed-result.log
grep -Fxq PASS /run/andeiva-routed-result.log
[[ -z $(find /run/andeiva-routed-namespace -mindepth 1 -maxdepth 1 -print -quit) ]]
ip -d -j link show > parent-after.json
[[ $(ip -j address show | jq '[.[].addr_info[]]|length') == 0 ]]
[[ $(ip -j route show table all | jq length) == 0 ]]
printf 'PASS isolated root link lifecycle; no addresses/routes installed\n'

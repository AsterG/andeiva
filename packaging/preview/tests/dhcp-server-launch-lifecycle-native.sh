#!/usr/bin/env bash
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
umask 077

# Root starts the otherwise absent reserved supervisor unit. This script never
# starts/stops an installed appliance, installs packages, or unsets AppArmor.
unit=andeiva-preview-grouped.service
[[ $EUID == 0 && -z ${CI:-} && ${ANDEIVA_KEA_LIFECYCLE_AUTHORIZED:-} == 1 ]] || exit 64
[[ $# == 1 && $1 == --namespace || $# == 2 && $1 == --isolated-lab ]] || exit 64
[[ ! -e /proc/sys/fs/binfmt_misc/WSLInterop && $(uname -r) != *[Mm]icrosoft* ]] || exit 64
grep -qx ID=debian /etc/os-release
grep -qx 'VERSION_ID="13"' /etc/os-release
[[ $(cat /proc/self/cgroup) == 0::/system.slice/andeiva-preview-grouped.service ]]

if [[ $1 == --namespace ]]; then
  lab=$(dirname -- "$(realpath -e -- "$0")")
  [[ $lab =~ ^/var/backups/andeiva-kea-lifecycle\.[A-Za-z0-9]{8}$ && $(stat -c '%u:%g:%a' "$lab") == 0:0:700 ]]
  # No mount or network mutation until all original namespace pins are distinct.
  for pair in '3 net' '4 mnt' '5 pid'; do
    read -r fd kind <<<"$pair"
    [[ $(readlink "/proc/self/fd/$fd") =~ ^$kind:\[[0-9]+\]$ ]]
    original=$(stat -Lc '%d:%i' "/proc/self/fd/$fd")
    current=$(stat -Lc '%d:%i' "/proc/self/ns/$kind")
    [[ $original == "$(stat -Lc '%d:%i' "/proc/1/ns/$kind")" ]]
    [[ $current != "$original" && $current == "$(stat -Lc '%d:%i' "/proc/thread-self/ns/$kind")" ]]
  done
  mount --make-rprivate /
  mount -t proc -o nosuid,nodev,noexec proc /proc
  [[ $$ == 1 ]]
  mount -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=8m tmpfs /run
  mkdir -m0700 /run/netns
  gateway=kea-lifecycle-gateway
  carrier=kea-lifecycle-carrier
  declare -A identities=()
  cleanup_namespace() {
    local rc=$? failed=0 name
    trap - EXIT
    exec 6<&- 7<&-
    for name in "$gateway" "$carrier"; do
      if [[ -n ${identities[$name]:-} ]]; then
        if [[ $(stat -Lc '%d:%i' "/run/netns/$name") != "${identities[$name]}" ]] || ! members=$(ip netns pids "$name") || [[ -n $members ]]; then
          failed=1
        else
          ip netns delete "$name" || failed=1
        fi
      fi
    done
    printf 'namespace_cleanup_failures=%s\n' "$failed" >"$lab/namespace-cleanup.txt"
    (( failed == 0 )) || rc=1
    exit "$rc"
  }
  trap cleanup_namespace EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  for name in "$gateway" "$carrier"; do
    ip netns add "$name"
    identities[$name]=$(stat -Lc '%d:%i' "/run/netns/$name")
    ip netns exec "$name" sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0
  done
  ip -n "$gateway" link add lan0 address 02:00:00:00:01:01 type veth peer name carrier0
  ip -n "$gateway" link set carrier0 netns "$carrier"
  ip -n "$carrier" link set carrier0 up
  ip -n "$gateway" link set lan0 up
  ip -n "$gateway" address add 198.18.1.1/24 dev lan0
  # No client, WAN, route out of these namespaces, forwarding or NAT permission.
  cat >"$lab/closed.nft" <<'NFT'
table inet kea_lifecycle_fixture {
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
NFT
  ip netns exec "$gateway" nft --check --file "$lab/closed.nft"
  ip netns exec "$gateway" nft --file "$lab/closed.nft"
  [[ -z $(ip netns pids "$gateway") && -z $(ip netns pids "$carrier") ]]
  exec 6<"/run/netns/$gateway" 7<"$lab/fixture"
  ANDEIVA_DHCP_SERVER_LIFECYCLE_NATIVE_V1=1 "$lab/native.test" \
    -test.run '^TestNativeRoutedDHCPServerLaunchLifecycleV1$' -test.count=1 -test.timeout=115s -test.v
  [[ -s $lab/fixture/lifecycle-result.json ]]
  jq -e '.version == 2 and .disabled_before_supervisor_exit == true and .mount_pins_closed_after_transfer == true and (.lease_files_verified | type == "number" and floor == . and . >= 1 and . <= 5) and (.samples|length)==7' "$lab/fixture/lifecycle-result.json" >/dev/null
  exit
fi

for tool in ip nft jq systemctl stat realpath sha256sum timeout unshare mount sysctl ss; do command -v "$tool" >/dev/null; done
[[ $(systemctl show "$unit" -p MainPID --value) == $$ ]]
[[ $(systemctl show "$unit" -p Transient --value) == yes ]]
[[ $(systemctl show "$unit" -p Delegate --value) == no ]]
[[ $(systemctl show "$unit" -p KillMode --value) == control-group ]]
[[ $(systemctl show "$unit" -p NoNewPrivileges --value) == yes ]]
[[ $(systemctl show "$unit" -p MemoryMax --value) == 268435456 ]]
[[ $(systemctl show "$unit" -p TasksMax --value) == 64 ]]
[[ $(systemctl show "$unit" -p LimitFSIZE --value) == 67108864 ]]
invocation=$(systemctl show "$unit" -p InvocationID --value)
[[ $invocation =~ ^[a-f0-9]{32}$ ]]
[[ $(systemctl show kea-dhcp4-server.service -p UnitFileState --value) == masked ]]
[[ $(systemctl show kea-dhcp4-server.service -p ActiveState --value) == inactive ]]
[[ $(systemctl show kea-dhcp4-server.service -p MainPID --value) == 0 ]]

protected() {
  local path=$1 mode
  [[ ! -L $path && $(stat -c '%u' "$path") == 0 ]]
  mode=$(stat -c '%a' "$path"); (( (8#$mode & 0022) == 0 ))
  mode=$(ls -ld -- "$path"); mode=${mode%% *}; [[ ${#mode} == 10 ]]
}
binary=$(realpath -e -- "$2")
[[ $binary == "$2" && -f $binary && -x $binary && $(stat -c '%h' "$binary") == 1 ]]
(( $(stat -c '%s' "$binary") > 0 && $(stat -c '%s' "$binary") <= 67108864 ))
protected "$binary"
parent=$(dirname -- "$binary")
while [[ $parent != / ]]; do protected "$parent"; parent=$(dirname -- "$parent"); done
self=$(realpath -e -- "$0"); protected "$self"
(( $(stat -c '%s' "$self") <= 65536 ))
parent=$(dirname -- "$self")
while [[ $parent != / ]]; do protected "$parent"; parent=$(dirname -- "$parent"); done
protected /var; protected /var/backups
lab=$(mktemp -d /var/backups/andeiva-kea-lifecycle.XXXXXXXX)
[[ $lab =~ ^/var/backups/andeiva-kea-lifecycle\.[A-Za-z0-9]{8}$ && $(stat -c '%u:%g:%a' "$lab") == 0:0:700 ]]
# Retain source inodes through copying; no computed recursive delete occurs.
exec {binary_fd}<"$binary" {self_fd}<"$self"
[[ $(stat -Lc '%d:%i' "/proc/$$/fd/$binary_fd") == "$(stat -Lc '%d:%i' "$binary")" ]]
cp -- "/proc/$$/fd/$binary_fd" "$lab/native.test"
cp -- "/proc/$$/fd/$self_fd" "$lab/driver.sh"
exec {binary_fd}<&- {self_fd}<&-
chmod 0555 "$lab/native.test" "$lab/driver.sh"
mkdir -m0700 "$lab/fixture"
sha256sum "$lab/native.test" "$lab/driver.sh" >"$lab/artifacts.sha256"
# Runtime file cap BEGIN
# Bash -f uses 1024-byte blocks outside POSIX mode. Verify kernel bytes too;
# inherited POSIXLY_CORRECT must not silently halve or enlarge the limit.
unset POSIXLY_CORRECT
set +o posix
ulimit -S -f 8192
ulimit -H -f 8192
runtime_file_limit_ok=false
while read -r first second third soft hard units rest; do
  if [[ $first == Max && $second == file && $third == size ]]; then
    [[ $soft == 8388608 && $hard == 8388608 && $units == bytes && -z $rest ]]
    runtime_file_limit_ok=true
  fi
done </proc/self/limits
[[ $runtime_file_limit_ok == true ]]
# Runtime file cap END
printf '%s\n' "$lab"

snapshot() {
  local phase=$1
  ip -j address show | jq -S 'walk(if type=="object" then del(.valid_life_time,.preferred_life_time) else . end)' >"$lab/$phase-addresses.json"
  for family in 4 6; do
    ip -j -"$family" route show table all | jq -S 'walk(if type=="object" then del(.expires) else . end)' >"$lab/$phase-routes$family.json"
    ip -j -"$family" rule show >"$lab/$phase-rules$family.json"
  done
  nft -j list ruleset | jq -S '.nftables |= map(select(has("metainfo")|not)) | walk(if type=="object" and has("counter") and (.counter|type)=="object" then .counter |= del(.packets,.bytes) else . end)' >"$lab/$phase-nft.json"
  cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding >"$lab/$phase-forwarding.txt"
  ip netns list >"$lab/$phase-netns.txt"
  cat /proc/1/mountinfo >"$lab/$phase-mountinfo.txt"
}
snapshot before
finish() {
  local rc=$? part
  trap - EXIT
  set +e
  snapshot after || rc=1
  for part in addresses.json routes4.json routes6.json rules4.json rules6.json nft.json forwarding.txt netns.txt mountinfo.txt; do
    cmp -- "$lab/before-$part" "$lab/after-$part" || rc=1
  done
  [[ $(systemctl show "$unit" -p InvocationID --value) == "$invocation" ]] || rc=1
  systemctl show "$unit" -p InvocationID -p CPUUsageNSec -p MemoryPeak -p TasksCurrent -p ControlGroup >"$lab/unit-resources.txt"
  printf 'exit_code=%s\n' "$rc" >"$lab/outer-result.txt"
  # On uncertainty preserve evidence and slots; containing unit owns drainage.
  exit "$rc"
}
trap finish EXIT
exec 3</proc/self/ns/net 4</proc/self/ns/mnt 5</proc/self/ns/pid
timeout --kill-after=5s 125s unshare --mount --net --pid --fork -- \
  /bin/bash "$lab/driver.sh" --namespace >"$lab/observations.log" 2>&1
grep -q -- '--- PASS: TestNativeRoutedDHCPServerLaunchLifecycleV1' "$lab/observations.log"
grep -q 'launcher_disable_before_unit_exit=true' "$lab/observations.log"
[[ $(cat "$lab/namespace-cleanup.txt") == namespace_cleanup_failures=0 ]]

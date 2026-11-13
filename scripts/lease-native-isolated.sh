#!/bin/bash
# Native Debian 13 lab only. The caller must own a bounded systemd cgroup with
# KillMode=control-group. No interface or routing change occurs in the host.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077
[[ $EUID == 0 && ${ANDEIVA_LEASE_LAB_AUTHORIZED:-} == 1 && -z ${CI:-} ]]
[[ ! -e /proc/sys/fs/binfmt_misc/WSLInterop && $(uname -r) != *[Mm]icrosoft* ]]
grep -qx 'ID=debian' /etc/os-release
grep -qx 'VERSION_ID="13"' /etc/os-release
for artifact in "$0" ./lease-native.test; do
  [[ -f $artifact && ! -L $artifact && $(stat -c '%u:%h' "$artifact") == 0:1 ]]
  mode=$(stat -c '%a' "$artifact")
  [[ $mode =~ ^[0-7]{3,4}$ ]]
  (( (8#$mode & 0022) == 0 ))
done
if [[ $# == 0 || ( $# == 1 && $1 == gate ) ]]; then
  profile=${1:-executor}
  [[ -x ./lease-native.test && -x /usr/bin/setpriv ]]
  # The original pins remain open across unshare and identity changes.
  exec 3</proc/self/ns/net
  exec 5</proc/self/ns/mnt
  exec 6</proc/self/ns/pid
  exec /usr/bin/unshare --mount --net --pid --fork -- /bin/bash "$0" isolated "$profile"
fi
[[ $# == 2 && $1 == isolated && ( $2 == executor || $2 == gate ) ]]
profile=$2
# Reject forged direct entry BEFORE mounting anything. /proc still names the
# original host PID namespace until all three provenance checks have passed.
for pair in '3 net' '5 mnt' '6 pid'; do
  read -r descriptor kind <<< "$pair"
  [[ $(readlink "/proc/self/fd/$descriptor") =~ ^$kind:\[[0-9]+\]$ ]]
  original=$(stat -Lc '%d:%i' "/proc/self/fd/$descriptor")
  current=$(stat -Lc '%d:%i' "/proc/self/ns/$kind")
  [[ $original == "$(stat -Lc '%d:%i' "/proc/1/ns/$kind")" ]]
  [[ $current != "$original" ]]
  [[ $current == "$(stat -Lc '%d:%i' "/proc/thread-self/ns/$kind")" ]]
done
/usr/bin/mount --make-rprivate /
/usr/bin/mount -t proc -o nosuid,nodev,noexec proc /proc
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
/usr/bin/mkdir -p /run/netns
/usr/bin/mkdir -m 0755 /run/andeiva-lease
/usr/bin/install -m 0555 ./lease-native.test /run/andeiva-lease/lease-native.test
exec 4</proc/self/ns/net
exec 5<&-
exec 6<&-
cleanup() {
  original=$?
  trap - EXIT
  /usr/bin/ip netns delete lease-peer || { printf 'lease native cleanup failed\n' >&2; exit 1; }
  exit "$original"
}
/usr/bin/ip netns add lease-peer
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Fixed sysctls are changed only after the separate target namespace is proven.
for path in /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/conf/all/forwarding /proc/sys/net/ipv4/conf/default/forwarding /proc/sys/net/ipv6/conf/all/forwarding /proc/sys/net/ipv6/conf/default/forwarding; do
  printf '0\n' > "$path"
done
printf '1\n' > /proc/sys/net/ipv6/conf/all/disable_ipv6
printf '1\n' > /proc/sys/net/ipv6/conf/default/disable_ipv6
# Leave loopback unconfigured; this executor deliberately rejects unrelated
# IPv4 addresses/routes, including automatic loopback configuration.
/usr/bin/ip link add lan0 address 02:00:00:00:01:01 type veth peer name peerlan
/usr/bin/ip link add wan0 address 02:00:00:00:02:01 type veth peer name peerwan
/usr/bin/ip link set peerlan netns lease-peer
/usr/bin/ip link set peerwan netns lease-peer
/usr/bin/ip -n lease-peer link set peerlan up
/usr/bin/ip -n lease-peer link set peerwan up
/usr/bin/ip link set lan0 up
/usr/bin/ip link set wan0 up
/usr/bin/ip -4 address add 198.18.0.1/24 dev lan0
for family in ipv4 ipv6; do
  for name in all default lan0 wan0; do
    [[ $(cat "/proc/sys/net/$family/conf/$name/forwarding") == 0 ]]
  done
done
cat >/run/andeiva-lease/deny.nft <<'EOF'
table inet andeiva_lease_qualification {
  chain input { type filter hook input priority 0; policy drop; }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy drop; }
}
EOF
/usr/sbin/nft -c -f /run/andeiva-lease/deny.nft
/usr/sbin/nft -f /run/andeiva-lease/deny.nft
/usr/bin/ip -4 -j address show > /run/andeiva-lease/addresses-before.json
/usr/bin/ip -4 -j route show table all > /run/andeiva-lease/routes-before.json
/usr/sbin/nft -j list ruleset > /run/andeiva-lease/firewall-before.json
if [[ $profile == gate ]]; then
  # The fixed helper exits without refreshing/removing its token. Observe the
  # actual kernel after the process has died, with forwarding still disabled.
  if ANDEIVA_LEASE_NATIVE=1 ANDEIVA_LEASE_ROLE=gate /usr/bin/setpriv \
    --reuid=62006 --regid=62006 --clear-groups --no-new-privs \
    --bounding-set=-all,+net_admin --inh-caps=-all,+net_admin --ambient-caps=-all,+net_admin \
    /run/andeiva-lease/lease-native.test -test.run '^TestNativeLeaseGateKernel$' -test.v -test.timeout 30s; then
    :
  else
    failed=$?
    # Privileged test evidence stays in the authorized laboratory log. Preserve
    # failure even if collecting diagnostics also fails.
    /usr/sbin/nft -j -n -y list table inet andeiva_lease_gate || :
    exit "$failed"
  fi
  /usr/sbin/nft -j -n -y list table inet andeiva_lease_gate > /run/andeiva-lease/gate-before-expiry.json
  jq -e 'any(.nftables[]; .set?.name=="enabled" and .set.elem==["wan0"]) and any(.nftables[]; .set?.name=="live" and (.set.elem|length)==1)' /run/andeiva-lease/gate-before-expiry.json >/dev/null
  sleep 13
  /usr/sbin/nft -j -n -y list table inet andeiva_lease_gate > /run/andeiva-lease/gate-after-expiry.json
  jq -e 'any(.nftables[]; .set?.name=="enabled" and .set.elem==["wan0"]) and any(.nftables[]; .set?.name=="live" and ((.set.elem // [])|length)==0)' /run/andeiva-lease/gate-after-expiry.json >/dev/null
  for family in ipv4 ipv6; do
    for name in all default lan0 wan0; do [[ $(cat "/proc/sys/net/$family/conf/$name/forwarding") == 0 ]]; done
  done
  printf 'PASS kernel lease token expired after helper exit; WAN retained until isolated namespace teardown; forwarding closed\n'
  exit 0
fi
# The capless negative runs in a different process from the narrow helper.
ANDEIVA_LEASE_NATIVE=1 ANDEIVA_LEASE_ROLE=capless /usr/bin/setpriv \
  --reuid=62006 --regid=62006 --clear-groups --no-new-privs \
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
  /run/andeiva-lease/lease-native.test -test.run '^TestNativeLeaseCaplessDenied$' -test.v -test.timeout 15s
/usr/bin/ip -4 -j address show > /run/andeiva-lease/addresses-capless.json
/usr/bin/ip -4 -j route show table all > /run/andeiva-lease/routes-capless.json
cmp /run/andeiva-lease/addresses-before.json /run/andeiva-lease/addresses-capless.json
cmp /run/andeiva-lease/routes-before.json /run/andeiva-lease/routes-capless.json
ANDEIVA_LEASE_NATIVE=1 ANDEIVA_LEASE_ROLE=helper /usr/bin/setpriv \
  --reuid=62006 --regid=62006 --clear-groups --no-new-privs \
  --bounding-set=-all,+net_admin --inh-caps=-all,+net_admin --ambient-caps=-all,+net_admin \
  /run/andeiva-lease/lease-native.test -test.run '^TestNativeLeaseLifecycle$' -test.v -test.timeout 90s
/usr/bin/ip -4 -j address show > /run/andeiva-lease/addresses-after.json
/usr/bin/ip -4 -j route show table all > /run/andeiva-lease/routes-after.json
/usr/sbin/nft -j list ruleset > /run/andeiva-lease/firewall-after.json
cmp /run/andeiva-lease/addresses-before.json /run/andeiva-lease/addresses-after.json
cmp /run/andeiva-lease/routes-before.json /run/andeiva-lease/routes-after.json
cmp /run/andeiva-lease/firewall-before.json /run/andeiva-lease/firewall-after.json
for family in ipv4 ipv6; do
  for name in all default lan0 wan0; do
    [[ $(cat "/proc/sys/net/$family/conf/$name/forwarding") == 0 ]]
  done
done
printf 'lease native: exact LAN/empty-WAN restoration, firewall unchanged, forwarding closed\n'

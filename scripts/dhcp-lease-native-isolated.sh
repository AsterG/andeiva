#!/bin/bash
# Authorized disposable Debian 13 lab only; bounded systemd cgroup required.
# Modes use fresh namespaces. No host/WAN interface or route is adopted.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077
[[ $EUID == 0 && ${ANDEIVA_DHCP_LEASE_LAB_AUTHORIZED:-} == 1 && -z ${CI:-} ]]
[[ ! -e /proc/sys/fs/binfmt_misc/WSLInterop && $(uname -r) != *[Mm]icrosoft* ]]
grep -qx 'ID=debian' /etc/os-release
grep -qx 'VERSION_ID="13"' /etc/os-release
for artifact in "$0" ./dhcp-lease-native.test ./andeiva-dhcp-hook; do
  [[ -f $artifact && ! -L $artifact && $(stat -c '%u:%h' "$artifact") == 0:1 ]]
  mode=$(stat -c '%a' "$artifact")
  [[ $mode =~ ^[0-7]{3,4}$ ]]
  (( (8#$mode & 0022) == 0 ))
done
if [[ $# == 1 && $1 != isolated ]]; then
  [[ $1 == lifecycle || $1 == owner-death || $1 == manager-death || $1 == broker-death ]]
  [[ -x ./dhcp-lease-native.test && -x ./andeiva-dhcp-hook && -x /usr/sbin/dhcpcd && -x /usr/bin/busybox && -x /usr/bin/setpriv ]]
  exec 3</proc/self/ns/net
  exec 4</proc/self/ns/mnt
  exec 6</proc/self/ns/pid
  exec /usr/bin/unshare --mount --net --pid --fork -- /bin/bash "$0" isolated "$1"
fi
[[ $# == 2 && $1 == isolated ]]
mode=$2
[[ $mode == lifecycle || $mode == owner-death || $mode == manager-death || $mode == broker-death ]]
# Reject direct entry BEFORE mounting. Original /proc identifies the host PID1.
for pair in '3 net' '4 mnt' '6 pid'; do
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
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /var/lib
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /usr/libexec
/usr/bin/mkdir -p /run/netns /run/dhcpcd /run/andeiva-dhcp /var/lib/dhcpcd
/usr/bin/mkdir -m 0755 /run/andeiva-dhcp-lease
for path in /run/dhcpcd /run/andeiva-dhcp /var/lib/dhcpcd; do
  /usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$path"
done
/usr/bin/install -m 0555 ./andeiva-dhcp-hook /usr/libexec/andeiva-dhcp-hook
/usr/bin/install -m 0555 ./dhcp-lease-native.test /run/andeiva-dhcp-lease/dhcp-lease-native.test
exec 5</proc/self/ns/net
exec 6<&-
server=
created_server=false
created_lan=false
cleanup() {
  original=$?
  trap - EXIT
  set +e
  clean=true
  # Do not signal a cached numeric PID. Exiting private PID1 terminates its
  # remaining descendants; the outer bounded cgroup owns final drain/reaping.
  if [[ $created_lan == true ]]; then /usr/bin/ip netns delete lease-lan || clean=false; fi
  if [[ $created_server == true ]]; then /usr/bin/ip netns delete dhcp-server || clean=false; fi
  if [[ $clean != true ]]; then printf 'integration namespace cleanup failed\n' >&2; exit 1; fi
  exit "$original"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/bin/ip netns add dhcp-server
created_server=true
/usr/bin/ip netns add lease-lan
created_lan=true
for path in /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/conf/all/forwarding /proc/sys/net/ipv4/conf/default/forwarding /proc/sys/net/ipv6/conf/all/forwarding /proc/sys/net/ipv6/conf/default/forwarding; do printf '0\n' > "$path"; done
printf '1\n' > /proc/sys/net/ipv6/conf/all/disable_ipv6
printf '1\n' > /proc/sys/net/ipv6/conf/default/disable_ipv6
# Loopback remains unconfigured; only the exact static LAN is initially present.
/usr/bin/ip link add lan0 address 02:00:00:00:01:01 type veth peer name peerlan
/usr/bin/ip link add wan0 address 02:00:00:00:02:01 type veth peer name srv0
/usr/bin/ip link set peerlan netns lease-lan
/usr/bin/ip link set srv0 netns dhcp-server
/usr/bin/ip -n lease-lan link set peerlan up
/usr/bin/ip -n dhcp-server link set srv0 up
/usr/bin/ip -n dhcp-server address add 198.19.0.2/24 dev srv0
/usr/bin/ip link set lan0 up
/usr/bin/ip link set wan0 up
/usr/bin/ip -4 address add 198.18.0.1/24 dev lan0
cat >/run/andeiva-dhcp-lease/deny.nft <<'EOF'
table inet andeiva_dhcp_lease_qualification {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "wan0" ip saddr 198.19.0.2 ip daddr { 255.255.255.255, 198.19.0.10 } udp sport 67 udp dport 68 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "wan0" ip daddr { 255.255.255.255, 198.19.0.2 } udp sport 68 udp dport 67 accept
  }
}
EOF
/usr/sbin/nft -c -f /run/andeiva-dhcp-lease/deny.nft
/usr/sbin/nft -f /run/andeiva-dhcp-lease/deny.nft
cat >/run/andeiva-dhcp/server.conf <<'EOF'
start 198.19.0.10
end 198.19.0.10
interface srv0
max_leases 1
min_lease 60
lease_file /run/andeiva-dhcp/server.leases
pidfile /run/andeiva-dhcp/server.pid
opt subnet 255.255.255.0
opt router 198.19.0.2
opt dns 198.19.0.2
opt lease 120
EOF
/usr/bin/ip netns exec dhcp-server /usr/bin/busybox udhcpd -f /run/andeiva-dhcp/server.conf >/run/andeiva-dhcp/server.log 2>&1 &
server=$!
/usr/bin/ip -4 -j address show > /run/andeiva-dhcp-lease/addresses-before.json
/usr/bin/ip -4 -j address show dev lan0 > /run/andeiva-dhcp-lease/lan-before.json
/usr/bin/ip -4 -j route show table all > /run/andeiva-dhcp-lease/routes-before.json
/usr/sbin/nft -j list ruleset > /run/andeiva-dhcp-lease/firewall-before.json
export ANDEIVA_DHCP_LEASE_NATIVE=1 ANDEIVA_DHCP_LEASE_MODE=$mode ANDEIVA_DHCP_LEASE_SERVER_PID=$server
unset ANDEIVA_DHCP_LEASE_ROLE
/run/andeiva-dhcp-lease/dhcp-lease-native.test -test.run '^TestNativeDHCPLeaseIntegration$' -test.v -test.timeout 5m
/usr/bin/ip -4 -j address show > /run/andeiva-dhcp-lease/addresses-after.json
/usr/bin/ip -4 -j address show dev lan0 > /run/andeiva-dhcp-lease/lan-after.json
/usr/bin/ip -4 -j route show table all > /run/andeiva-dhcp-lease/routes-after.json
/usr/sbin/nft -j list ruleset > /run/andeiva-dhcp-lease/firewall-after.json
cmp /run/andeiva-dhcp-lease/lan-before.json /run/andeiva-dhcp-lease/lan-after.json
cmp /run/andeiva-dhcp-lease/firewall-before.json /run/andeiva-dhcp-lease/firewall-after.json
if [[ $mode != manager-death && $mode != broker-death ]]; then
  cmp /run/andeiva-dhcp-lease/addresses-before.json /run/andeiva-dhcp-lease/addresses-after.json
  cmp /run/andeiva-dhcp-lease/routes-before.json /run/andeiva-dhcp-lease/routes-after.json
fi
for family in ipv4 ipv6; do
  for name in all default lan0 wan0; do [[ $(cat "/proc/sys/net/$family/conf/$name/forwarding") == 0 ]]; done
done
printf 'DHCP/LeaseExecutor integration mode=%s: LAN preserved, firewall unchanged, forwarding closed\n' "$mode"

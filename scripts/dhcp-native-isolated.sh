#!/bin/bash
# Native Debian laboratory only. Invoke from a bounded systemd service whose
# cgroup owns all descendants; never invoke this in WSL or a customer appliance.
set -euo pipefail
if [[ ${EUID} != 0 || ${ANDEIVA_DHCP_LAB_AUTHORIZED:-} != 1 ]]; then exit 64; fi
if [[ -e /proc/sys/fs/binfmt_misc/WSLInterop ]] || [[ $(uname -r) == *[Mm]icrosoft* ]]; then exit 64; fi
if [[ $# == 0 ]]; then
  [[ -x /usr/sbin/dhcpcd && -x /usr/bin/busybox ]]
  [[ -x ./dhcp-native.test && -x ./andeiva-dhcp-hook ]]
  # Descriptor provenance is established before either namespace is created.
  exec 3</proc/self/ns/net
  exec 4</proc/self/ns/mnt
  exec 5</proc/self/ns/pid
  exec /usr/bin/unshare --mount --net --pid --fork -- /bin/bash "$0" isolated
fi
[[ $# == 1 && $1 == isolated ]]
# Reject direct entry before any mount operation. The retained descriptors must
# identify this laboratory host, while both current namespaces must be private.
[[ $(readlink /proc/self/fd/3) =~ ^net:\[[0-9]+\]$ ]]
[[ $(readlink /proc/self/fd/4) =~ ^mnt:\[[0-9]+\]$ ]]
[[ $(readlink /proc/self/fd/5) =~ ^pid:\[[0-9]+\]$ ]]
for pair in '3 net' '4 mnt' '5 pid'; do
  read -r descriptor kind <<< "$pair"
  original=$(stat -Lc '%d:%i' "/proc/self/fd/$descriptor")
  current=$(stat -Lc '%d:%i' "/proc/self/ns/$kind")
  [[ $original == "$(stat -Lc '%d:%i' "/proc/1/ns/$kind")" ]]
  [[ $current != "$original" ]]
  [[ $current == "$(stat -Lc '%d:%i' "/proc/thread-self/ns/$kind")" ]]
done
/usr/bin/mount --make-rprivate /
# PID isolation prevents a recycled server PID from addressing a host process.
# Mount proc only after checking the retained host namespace references above.
/usr/bin/mount -t proc -o nosuid,nodev,noexec proc /proc
# All engine state paths are replaced only in this private mount namespace.
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /var/lib
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /usr/libexec
/usr/bin/mkdir -p /run/dhcpcd /run/andeiva-dhcp /run/netns /var/lib/dhcpcd
for path in /run/dhcpcd /run/andeiva-dhcp /var/lib/dhcpcd; do
  /usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$path"
done
/usr/bin/install -m 0555 ./andeiva-dhcp-hook /usr/libexec/andeiva-dhcp-hook
/usr/bin/ip link set lo up
/usr/bin/ip netns add dhcp-server
/usr/bin/ip link add wan0 type veth peer name srv0
/usr/bin/ip link set srv0 netns dhcp-server
/usr/bin/ip link set wan0 up
/usr/bin/ip netns exec dhcp-server /usr/bin/ip link set lo up
/usr/bin/ip netns exec dhcp-server /usr/bin/ip link set srv0 up
/usr/bin/ip netns exec dhcp-server /usr/bin/ip address add 198.18.1.1/24 dev srv0
/usr/bin/ip link add lan0 type dummy
/usr/bin/ip link set lan0 up
/usr/bin/ip address add 198.19.0.1/24 dev lan0
cat >/run/andeiva-dhcp/server.conf <<'EOF'
start 198.18.1.10
end 198.18.1.10
interface srv0
max_leases 1
min_lease 60
lease_file /run/andeiva-dhcp/server.leases
pidfile /run/andeiva-dhcp/server.pid
opt subnet 255.255.255.0
opt router 198.18.1.1
opt dns 198.18.1.1
opt lease 120
EOF
/usr/bin/ip netns exec dhcp-server /usr/bin/busybox udhcpd -f /run/andeiva-dhcp/server.conf >/run/andeiva-dhcp/server.log 2>&1 &
server=$!
cleanup() {
  kill "$server" 2>/dev/null || true
  wait "$server" 2>/dev/null || true
  /usr/bin/ip netns del dhcp-server 2>/dev/null || true
}
trap cleanup EXIT
export ANDEIVA_DHCP_SERVER_PID=$server ANDEIVA_DHCP_NATIVE=1
./dhcp-native.test -test.run '^TestNativeDHCPCDOwner$' -test.v -test.timeout 5m

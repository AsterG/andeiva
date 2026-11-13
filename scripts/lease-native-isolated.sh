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
if [[ $# == 0 || ( $# == 1 && ( $1 == gate || $1 == gate-traffic ) ) ]]; then
  profile=${1:-executor}
  [[ -x ./lease-native.test && -x /usr/bin/setpriv ]]
  # The original pins remain open across unshare and identity changes.
  exec 3</proc/self/ns/net
  exec 5</proc/self/ns/mnt
  exec 6</proc/self/ns/pid
  if [[ $profile == gate-traffic ]]; then
    exec /usr/bin/timeout --signal=TERM --kill-after=2s 43s /usr/bin/unshare --mount --net --pid --fork --kill-child=KILL -- /bin/bash "$0" isolated "$profile"
  fi
  exec /usr/bin/unshare --mount --net --pid --fork -- /bin/bash "$0" isolated "$profile"
fi
[[ $# == 2 && $1 == isolated && ( $2 == executor || $2 == gate || $2 == gate-traffic ) ]]
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
server_pid= client_pid= wan_created=false
cleanup() {
  original=$?
  trap - EXIT
  if [[ $profile == gate-traffic ]]; then
    printf '0\n' > /proc/sys/net/ipv4/ip_forward
    if (( original != 0 )); then
      for log in /run/andeiva-lease/traffic-server.log /run/andeiva-lease/traffic-client.log; do
        if [[ -f $log ]]; then head -c 32768 "$log"; fi
      done
    fi
    for child in "$server_pid" "$client_pid"; do
      if [[ $child =~ ^[0-9]+$ ]] && (( child > 1 )); then
        kill -KILL "$child" 2>/dev/null || :
        wait "$child" 2>/dev/null || :
      fi
    done
    if [[ $wan_created == true ]]; then
      /usr/bin/ip netns delete lease-wan || { printf 'lease WAN cleanup failed\n' >&2; exit 1; }
    fi
  fi
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
if [[ $profile == gate-traffic ]]; then
  /usr/bin/ip netns add lease-wan
  wan_created=true
  /usr/bin/ip -n lease-peer link set peerwan netns lease-wan
  for peer in lease-peer lease-wan; do
    /usr/bin/ip netns exec "$peer" /usr/sbin/sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0 net.ipv6.conf.default.forwarding=0 net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
  done
  /usr/bin/ip -n lease-peer -4 address add 198.18.0.2/24 dev peerlan
  /usr/bin/ip -n lease-peer -4 route add default via 198.18.0.1 dev peerlan
  /usr/bin/ip -n lease-wan link set peerwan up
  /usr/bin/ip -n lease-wan -4 address add 198.19.0.2/24 dev peerwan
  /usr/bin/ip -n lease-wan -4 route add 198.18.0.0/24 via 198.19.0.10 dev peerwan
fi
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
if [[ $profile == gate-traffic ]]; then
  # These qualification accepts would otherwise carry established TCP/UDP past
  # lease expiry. The independent priority -300 gate must dominate them.
  cat >/run/andeiva-lease/traffic.nft <<'EOF'
add rule inet andeiva_lease_qualification forward ct state established,related counter accept
add rule inet andeiva_lease_qualification forward iifname "lan0" oifname "wan0" ip saddr 198.18.0.2 ip daddr 198.19.0.2 tcp dport 18080 counter accept
add rule inet andeiva_lease_qualification forward iifname "lan0" oifname "wan0" ip saddr 198.18.0.2 ip daddr 198.19.0.2 udp dport 18081 counter accept
EOF
  /usr/sbin/nft -c -f /run/andeiva-lease/traffic.nft
  /usr/sbin/nft -f /run/andeiva-lease/traffic.nft
  /usr/sbin/nft -j -n -y list table inet andeiva_lease_qualification > /run/andeiva-lease/traffic-policy.json
  jq -e '
    [.nftables[]|select(has("chain"))|.chain] as $chains |
    [.nftables[]|select(has("rule"))|.rule] as $rules |
    ($chains|length)==3 and all($chains[]; .policy=="drop" and .prio==0 and .type=="filter" and .name==.hook) and
    ([$chains[].name]|sort)==["forward","input","output"] and
    ($rules|length)==3 and all($rules[]; .family=="inet" and .table=="andeiva_lease_qualification" and .chain=="forward" and .expr[-1]=={"accept":null} and (.expr[-2]|has("counter"))) and
    $rules[0].expr[0].match.left=={"ct":{"key":"state"}} and
    ($rules[0].expr|length)==3 and
    ($rules[0].expr[0].match.right as $states | $states==[2,4] or $states=={"set":[2,4]} or $states==["established","related"] or $states=={"set":["established","related"]}) and
    all($rules[1:][]; any(.expr[]; .match.left=={"meta":{"key":"iifname"}} and .match.right=="lan0") and any(.expr[]; .match.left=={"meta":{"key":"oifname"}} and .match.right=="wan0") and any(.expr[]; .match.left=={"payload":{"protocol":"ip","field":"saddr"}} and .match.right=="198.18.0.2") and any(.expr[]; .match.left=={"payload":{"protocol":"ip","field":"daddr"}} and .match.right=="198.19.0.2")) and
    any($rules[1].expr[]; .match.left=={"payload":{"protocol":"tcp","field":"dport"}} and .match.right==18080) and
    any($rules[2].expr[]; .match.left=={"payload":{"protocol":"udp","field":"dport"}} and .match.right==18081)
  ' /run/andeiva-lease/traffic-policy.json >/dev/null
  publish_phase() {
    [[ $1 == before || $1 == expired || $1 == stop ]]
    [[ ! -e /run/andeiva-lease/traffic-phase.new ]]
    ( set -o noclobber; printf '%s\n' "$1" > /run/andeiva-lease/traffic-phase.new )
    chmod 0644 /run/andeiva-lease/traffic-phase.new
    mv -T /run/andeiva-lease/traffic-phase.new /run/andeiva-lease/traffic-phase
  }
  publish_phase before
  ANDEIVA_LEASE_NATIVE=1 ANDEIVA_LEASE_ROLE=traffic-server /usr/bin/ip netns exec lease-wan /usr/bin/setpriv \
    --reuid=62007 --regid=62007 --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
    /run/andeiva-lease/lease-native.test -test.run '^TestNativeLeaseGateTrafficServer$' -test.v -test.timeout 40s > /run/andeiva-lease/traffic-server.log 2>&1 &
  server_pid=$!
  for attempt in {1..50}; do
    kill -0 "$server_pid"
    if grep -q 'TRAFFIC_SERVER_READY' /run/andeiva-lease/traffic-server.log; then break; fi
    sleep 0.1
  done
  grep -q 'TRAFFIC_SERVER_READY' /run/andeiva-lease/traffic-server.log
fi
if [[ $profile == gate || $profile == gate-traffic ]]; then
  helper_timeout=30s
  if [[ $profile == gate-traffic ]]; then helper_timeout=15s; fi
  # The fixed helper exits without refreshing/removing its token. Observe the
  # actual kernel after the process has died, with forwarding still disabled.
  if ANDEIVA_LEASE_NATIVE=1 ANDEIVA_LEASE_ROLE=gate /usr/bin/setpriv \
    --reuid=62006 --regid=62006 --clear-groups --no-new-privs \
    --bounding-set=-all,+net_admin --inh-caps=-all,+net_admin --ambient-caps=-all,+net_admin \
    /run/andeiva-lease/lease-native.test -test.run '^TestNativeLeaseGateKernel$' -test.v -test.timeout "$helper_timeout" | tee /run/andeiva-lease/gate-helper.log; then
    :
  else
    failed=$?
    # Privileged test evidence stays in the authorized laboratory log. Preserve
    # failure even if collecting diagnostics also fails.
    /usr/sbin/nft -j -n -y list table inet andeiva_lease_gate || :
    exit "$failed"
  fi
  grep -q '^--- PASS: TestNativeLeaseGateKernel ' /run/andeiva-lease/gate-helper.log
  ! grep -q '^--- SKIP:' /run/andeiva-lease/gate-helper.log
  /usr/sbin/nft -j -n -y list table inet andeiva_lease_gate > /run/andeiva-lease/gate-before-expiry.json
  jq -e 'any(.nftables[]; .set?.name=="enabled" and .set.elem==["wan0"]) and any(.nftables[]; .set?.name=="live" and (.set.elem|length)==1)' /run/andeiva-lease/gate-before-expiry.json >/dev/null
  if [[ $profile == gate-traffic ]]; then
    # The helper has exited successfully before opening the isolated IP path.
    # Preserve its exact gate structure throughout; only expiry may remove live.
    jq -S '.nftables |= map(select(has("metainfo")|not)) | .nftables |= map(if has("set") then .set |= del(.elem) else . end)' /run/andeiva-lease/gate-before-expiry.json > /run/andeiva-lease/gate-structure-before.json
    /usr/bin/ip -4 -j address show dev lan0 > /run/andeiva-lease/traffic-lan-before.json
    /usr/bin/ip -4 -j address show > /run/andeiva-lease/traffic-addresses-before.json
    /usr/bin/ip -4 -j route show table all > /run/andeiva-lease/traffic-routes-before.json
    for scope in all default lan0 wan0; do [[ $(cat "/proc/sys/net/ipv6/conf/$scope/forwarding") == 0 ]]; done
    printf '1\n' > /proc/sys/net/ipv4/ip_forward
    [[ $(cat /proc/sys/net/ipv4/ip_forward) == 1 ]]
    ANDEIVA_LEASE_NATIVE=1 ANDEIVA_LEASE_ROLE=traffic-client /usr/bin/ip netns exec lease-peer /usr/bin/setpriv \
      --reuid=62007 --regid=62007 --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
      /run/andeiva-lease/lease-native.test -test.run '^TestNativeLeaseGateTrafficClient$' -test.v -test.timeout 28s > /run/andeiva-lease/traffic-client.log 2>&1 &
    client_pid=$!
    for attempt in {1..50}; do
      kill -0 "$client_pid"; kill -0 "$server_pid"
      if grep -q 'TRAFFIC_PRE_EXPIRY_PASS' /run/andeiva-lease/traffic-client.log; then break; fi
      sleep 0.1
    done
    grep -q 'TRAFFIC_PRE_EXPIRY_PASS' /run/andeiva-lease/traffic-client.log
    for attempt in {1..75}; do
      kill -0 "$client_pid"; kill -0 "$server_pid"
      /usr/sbin/nft -j -n -y list table inet andeiva_lease_gate > /run/andeiva-lease/gate-after-expiry.json
      if jq -e 'any(.nftables[]; .set?.name=="enabled" and .set.elem==["wan0"]) and any(.nftables[]; .set?.name=="live" and ((.set.elem // [])|length)==0)' /run/andeiva-lease/gate-after-expiry.json >/dev/null; then break; fi
      sleep 0.2
    done
    jq -e 'any(.nftables[]; .set?.name=="enabled" and .set.elem==["wan0"]) and any(.nftables[]; .set?.name=="live" and ((.set.elem // [])|length)==0)' /run/andeiva-lease/gate-after-expiry.json >/dev/null
    jq -S '.nftables |= map(select(has("metainfo")|not)) | .nftables |= map(if has("set") then .set |= del(.elem) else . end)' /run/andeiva-lease/gate-after-expiry.json > /run/andeiva-lease/gate-structure-after.json
    cmp /run/andeiva-lease/gate-structure-before.json /run/andeiva-lease/gate-structure-after.json
    publish_phase expired
    if wait "$client_pid"; then client_pid=; else failed=$?; client_pid=; exit "$failed"; fi
    cat /run/andeiva-lease/traffic-client.log
    grep -q 'TRAFFIC_POST_EXPIRY_PASS' /run/andeiva-lease/traffic-client.log
    grep -q '^--- PASS: TestNativeLeaseGateTrafficClient ' /run/andeiva-lease/traffic-client.log
    ! grep -q '^--- SKIP:' /run/andeiva-lease/traffic-client.log
    kill -0 "$server_pid"
    publish_phase stop
    if wait "$server_pid"; then server_pid=; else failed=$?; server_pid=; exit "$failed"; fi
    cat /run/andeiva-lease/traffic-server.log
    grep -q '^--- PASS: TestNativeLeaseGateTrafficServer ' /run/andeiva-lease/traffic-server.log
    ! grep -q '^--- SKIP:' /run/andeiva-lease/traffic-server.log
    /usr/bin/ip -4 -j address show dev lan0 > /run/andeiva-lease/traffic-lan-after.json
    cmp /run/andeiva-lease/traffic-lan-before.json /run/andeiva-lease/traffic-lan-after.json
    /usr/bin/ip -4 -j address show > /run/andeiva-lease/traffic-addresses-after.json
    /usr/bin/ip -4 -j route show table all > /run/andeiva-lease/traffic-routes-after.json
    cmp /run/andeiva-lease/traffic-addresses-before.json /run/andeiva-lease/traffic-addresses-after.json
    cmp /run/andeiva-lease/traffic-routes-before.json /run/andeiva-lease/traffic-routes-after.json
    /usr/sbin/nft -j -n -y list table inet andeiva_lease_qualification > /run/andeiva-lease/traffic-policy-after.json
    for when in '' '-after'; do
      jq -S '.nftables |= map(select(has("metainfo")|not)) | walk(if type=="object" and has("counter") then .counter |= del(.packets,.bytes) else . end)' "/run/andeiva-lease/traffic-policy$when.json" > "/run/andeiva-lease/traffic-policy$when-normalized.json"
    done
    cmp /run/andeiva-lease/traffic-policy-normalized.json /run/andeiva-lease/traffic-policy-after-normalized.json
    jq -e 'any(.nftables[]; .rule?.expr[0].match.left.ct.key=="state" and any(.rule.expr[]; .counter?.packets>0))' /run/andeiva-lease/traffic-policy-after.json >/dev/null
    [[ $(cat /proc/sys/net/ipv4/ip_forward) == 1 ]]
    for scope in all default lan0 wan0; do [[ $(cat "/proc/sys/net/ipv6/conf/$scope/forwarding") == 0 ]]; done
    printf '0\n' > /proc/sys/net/ipv4/ip_forward
    printf 'PASS real TCP/UDP before expiry and timeout after kernel token expiry with helper exited; established accept retained; isolated traffic only\n'
    exit 0
  fi
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

#!/bin/bash
# Explicit laboratory qualification; never invoked by appliance startup or CI.
set -euo pipefail

fail() { printf '%s\n' 'ANDEIVA_RESERVE_QUALIFICATION_REFUSED' >&2; exit 64; }
[[ $EUID = 0 ]] || fail

if [[ ${1:-} = --inside-isolated-lab ]]; then
  [[ $# = 3 ]] || fail
  lab=$2
  account=$3
  [[ $(readlink /proc/self/ns/mnt) != "$(readlink /proc/1/ns/mnt)" && $(readlink /proc/self/ns/net) != "$(readlink /proc/1/ns/net)" ]] || fail
  [[ $lab =~ ^/var/backups/andeiva-reserve-qualification\.[A-Za-z0-9]+$ && ! -L $lab && -d $lab ]] || fail
  [[ $(stat -c %u "$lab") = 0 && $(stat -c %a "$lab") = 711 ]] || fail
  [[ $account =~ ^[a-z_][a-z0-9_-]{0,31}$ && $(id -u "$account") != 0 ]] || fail
  cleanup() {
    result=$?
    trap - EXIT
    if mountpoint -q "$lab/mount"; then
      umount "$lab/mount" || result=1
    fi
    exit "$result"
  }
  trap cleanup EXIT
  [[ ! -e $lab/volume.img && ! -L $lab/volume.img && ! -e $lab/mount && ! -L $lab/mount ]] || fail
  fallocate -l 64M "$lab/volume.img"
  /usr/sbin/mke2fs -q -t ext4 -F -N 2048 -m 0 "$lab/volume.img"
  mkdir -m 700 "$lab/mount"
  mount -t ext4 -o loop,nosuid,nodev,noexec "$lab/volume.img" "$lab/mount"
  chown "$account:$account" "$lab/mount"
  chmod 700 "$lab/mount"
  mkdir -m 700 "$lab/work"
  chown "$account:$account" "$lab/work"
  result=0
  setpriv --reuid="$account" --regid="$account" --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs \
    env TMPDIR="$lab/work" ANDEIVA_RESERVE_NATIVE_QUALIFY=1 ANDEIVA_RESERVE_NATIVE_AREA="$lab/mount" \
    "$lab/reserve.test" -test.run '^TestNativeReservePressure$' -test.v -test.count=1 -test.timeout=3m > "$lab/tests.log" 2>&1 || result=$?
  cat "$lab/tests.log"
  [[ $result = 0 ]] || exit "$result"
  if grep -Eq 'no tests to run|--- SKIP:|^SKIP|^FAIL' "$lab/tests.log"; then fail; fi
  for name in TestNativeReservePressure TestNativeReservePressure/bytes TestNativeReservePressure/inodes; do
    grep -Eq "^=== RUN[[:space:]]+$name$" "$lab/tests.log" || fail
    grep -Eq "^[[:space:]]*--- PASS: $name \\([^)]+\\)$" "$lab/tests.log" || fail
  done
  exit
fi

[[ $# = 4 && $1 = --qualify-isolated-ext4 ]] || fail
binary=$2
checksum=$3
account=$4
[[ $binary =~ ^/[A-Za-z0-9_./-]+$ && $(readlink -e "$binary") = "$binary" && -f $binary ]] || fail
[[ $(stat -c %u "$binary") = 0 && $(stat -c %h "$binary") = 1 ]] || fail
mode=$(stat -c %a "$binary")
(( (8#$mode & 0022) == 0 )) || fail
parent=$(dirname "$binary")
while :; do
  [[ $(stat -c %u "$parent") = 0 ]] || fail
  mode=$(stat -c %a "$parent")
  (( (8#$mode & 0022) == 0 )) || fail
  [[ $parent = / ]] && break
  parent=$(dirname "$parent")
done
[[ $checksum =~ ^[a-f0-9]{64}$ && $account =~ ^[a-z_][a-z0-9_-]{0,31}$ && $(id -u "$account") != 0 ]] || fail
printf '%s  %s\n' "$checksum" "$binary" | sha256sum --check --status || fail
# The harness supports Debian 13 laboratory machines, independently of hypervisor.
[[ -r /usr/lib/os-release ]] || fail
grep -qx 'ID=debian' /usr/lib/os-release || fail
grep -qx 'VERSION_ID="13"' /usr/lib/os-release || fail
lab=$(mktemp -d /var/backups/andeiva-reserve-qualification.XXXXXXXX)
chmod 711 "$lab"
install -o root -g root -m 755 "$binary" "$lab/reserve.test"
printf '%s  %s\n' "$checksum" "$lab/reserve.test" | sha256sum --check --status || fail
script=$(readlink -e "$0")
install -o root -g root -m 700 "$script" "$lab/qualify.sh"
printf 'QUALIFICATION_DIRECTORY=%s\n' "$lab"
unshare --mount --net --propagation private -- /bin/bash "$lab/qualify.sh" --inside-isolated-lab "$lab" "$account"

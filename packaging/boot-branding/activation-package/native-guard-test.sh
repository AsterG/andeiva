#!/usr/bin/env bash
# Authorized Debian laboratory only. Does not install packages or run APT.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C
unset BASH_ENV ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH APT_CONFIG
fail() { printf '%s\n' "$1" >&2; exit 1; }
(( EUID == 0 && $# == 3 )) || fail 'Usage: native-guard-test.sh ROOT_OWNED_DEB TRUSTED_DEB_SHA256 TRUSTED_BINARY_SHA256'
deb=$1
[[ "$deb" = /* && "$deb" != *$'\n'* && "$2" =~ ^[0-9a-f]{64}$ && "$3" =~ ^[0-9a-f]{64}$ ]] || fail ANDEIVA_GUARD_TEST_INPUT
secure() {
  local item=$1 permission
  while :; do
    [[ -e "$item" && ! -L "$item" && $(stat -c %u -- "$item") = 0 ]] || fail ANDEIVA_GUARD_TEST_UNSAFE_PATH
    permission=$(stat -c %a -- "$item")
    (( (8#$permission & 022) == 0 )) || fail ANDEIVA_GUARD_TEST_UNSAFE_MODE
    [[ "$item" != / ]] || break
    item=$(dirname -- "$item")
  done
}
secure "$deb"
secure /var/backups/andeiva-boot-branding/lock
[[ -f "$deb" && $(stat -c %s -- "$deb") -le 8388608 ]] || fail ANDEIVA_GUARD_TEST_DEB
actual=$(sha256sum -- "$deb"); [[ "${actual%% *}" = "$2" ]] || fail ANDEIVA_GUARD_TEST_DEB_HASH
[[ $(df -B1 --output=avail /var/backups | tail -n1 | tr -d ' ') -gt 1073741824 ]] || fail ANDEIVA_GUARD_TEST_CAPACITY
! pgrep -x 'apt|apt-get|dpkg' >/dev/null || fail ANDEIVA_GUARD_TEST_PACKAGE_PROCESS
directory=/var/backups/andeiva-boot-offline
[[ ! -e "$directory" && ! -L "$directory" ]] || fail ANDEIVA_GUARD_TEST_EXISTING_OFFLINE_STATE
stage=$(mktemp -d /var/backups/andeiva-offline-guard-test.XXXXXXXX)
printf 'Private test evidence: %s\n' "$stage"
# Failure deliberately retains evidence and any marker; never guess recovery.
trap 'printf "ANDEIVA_GUARD_TEST_INTERRUPTED: inspect retained evidence at %s\n" "$stage" >&2' ERR
( set -C; timeout --kill-after=2 15 /bin/bash -o pipefail -c \
  'dpkg-deb --fsys-tarfile "$1" | tar -xOf - ./usr/sbin/andeiva-boot-activation | head -c 8388609' sh "$deb" > "$stage/activation" )
[[ -s "$stage/activation" && $(stat -c %s "$stage/activation") -le 8388608 ]] || fail ANDEIVA_GUARD_TEST_BINARY_SIZE
actual=$(sha256sum "$stage/activation"); [[ "${actual%% *}" = "$3" ]] || fail ANDEIVA_GUARD_TEST_BINARY_HASH
chmod 0700 "$stage/activation"
[[ $(timeout 10 "$stage/activation" capabilities) = '{"offline_install_guard":1}' ]] || fail ANDEIVA_GUARD_TEST_CAPABILITY
kernel=$(uname -r)
[[ "$kernel" =~ ^[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+~-]{0,96}$ ]] || fail ANDEIVA_GUARD_TEST_KERNEL
targets=(/var/backups/andeiva-boot-branding/journal.json /boot/grub/grub.cfg "/boot/initrd.img-$kernel" /etc/plymouth/plymouthd.conf /etc/default/grub.d/99-andeiva-branding.cfg)
for target in "${targets[@]}"; do secure "$target"; [[ -f "$target" ]] || fail ANDEIVA_GUARD_TEST_TARGET; done
sha256sum -- "${targets[@]}" > "$stage/before.sha256"
timeout 10 "$stage/activation" status > "$stage/status-before.json"
exec 8<>/var/backups/andeiva-boot-branding/lock
flock -n 8 || fail ANDEIVA_GUARD_TEST_BUSY
mkdir -m0700 -- "$directory"
( set -C; printf 'ANDEIVA guard test only: %s\n' "$stage" > "$directory/install-pending" )
sync -f "$directory/install-pending"
sync -f "$directory"
sha256sum "$directory/install-pending" > "$stage/marker.sha256"
flock -u 8
exec 8>&-
for operation in preflight prepare apply restore; do
  args=("$operation")
  [[ "$operation" != prepare ]] || args+=(--recovery-verified)
  if timeout --kill-after=2 10 "$stage/activation" "${args[@]}" > "$stage/$operation.out" 2> "$stage/$operation.err"; then
    fail ANDEIVA_GUARD_TEST_MUTATION_ACCEPTED
  else
    result=$?
    (( result == 1 )) || fail ANDEIVA_GUARD_TEST_UNEXPECTED_EXIT
    [[ $(cat "$stage/$operation.err") = ANDEIVA_BOOT_OFFLINE_INSTALL_PENDING ]] || fail ANDEIVA_GUARD_TEST_WRONG_REFUSAL
    [[ ! -s "$stage/$operation.out" ]] || fail ANDEIVA_GUARD_TEST_UNEXPECTED_OUTPUT
  fi
done
[[ $(timeout 10 "$stage/activation" capabilities) = '{"offline_install_guard":1}' ]] || fail ANDEIVA_GUARD_TEST_CAPABILITY_BLOCKED
timeout 10 "$stage/activation" status > "$stage/status-after.json"
cmp "$stage/status-before.json" "$stage/status-after.json"
exec 8<>/var/backups/andeiva-boot-branding/lock
flock -n 8 || fail ANDEIVA_GUARD_TEST_BUSY
sha256sum -c "$stage/before.sha256" > "$stage/unchanged.log"
! pgrep -x 'apt|apt-get|dpkg' >/dev/null || fail ANDEIVA_GUARD_TEST_PACKAGE_PROCESS
[[ ! -L "$directory/install-pending" && $(stat -c '%u:%a' "$directory/install-pending") = 0:600 ]] || fail ANDEIVA_GUARD_TEST_MARKER_CHANGED
sha256sum -c "$stage/marker.sha256" > "$stage/marker-check.log"
rm -- "$directory/install-pending"
sync -f "$directory"
rmdir -- "$directory"
sync -f /var/backups
trap - ERR
printf '%s\n' ANDEIVA_STAGED_OFFLINE_GUARD_PASS

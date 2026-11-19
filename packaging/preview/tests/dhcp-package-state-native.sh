#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset BASH_ENV ENV LD_PRELOAD LD_LIBRARY_PATH
umask 077

if [[ $# != 2 || $1 != --isolated-lab || $EUID != 0 ]]; then
  echo 'Usage: dhcp-package-state-native.sh --isolated-lab PACKAGE (root on Debian)' >&2
  exit 2
fi

package=$(realpath -e -- "$2")
[[ $(dpkg-deb -f "$package" Package) = andeiva-firewall-preview ]]
unprivileged_uid=$(id -u nobody)
unprivileged_gid=$(id -g nobody)
[[ $unprivileged_uid != 0 && $unprivileged_gid != 0 ]]
kea_account=$(getent passwd _kea)
kea_group=$(getent group _kea)

stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
dpkg-deb -x "$package" "$stage/root"
install -d -m 0755 "$stage/etc" "$stage/etc/andeiva-preview"
printf '%s\n' "$kea_account" >"$stage/etc/passwd"
printf '%s\n' "$kea_group" >"$stage/etc/group"
printf 'passwd: files\ngroup: files\n' >"$stage/etc/nsswitch.conf"
install -m 0644 "$stage/root/etc/andeiva-preview/config.json.example" "$stage/etc/andeiva-preview/config.json"
install -m 0555 "$stage/root/usr/lib/andeiva-preview/andeiva-preview" "$stage/andeiva-preview"
chmod 0711 "$stage"

unshare --net --mount --propagation private bash -eu -c '
  stage=$1
  mount --bind "$stage/etc" /etc
  mount -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=4m tmpfs /var/lib
  install -d -m 0700 /var/lib/andeiva-preview-package
  state=/var/lib/andeiva-preview-package/dhcp-server/leases
  "$stage/andeiva-preview" grouped-dhcp-state
  [[ $(stat -c "%U:%G:%a" "$state") = _kea:_kea:700 ]]
  printf "retained\n" >"$state/lease-proof"
  "$stage/andeiva-preview" grouped-dhcp-state
  [[ $(cat "$state/lease-proof") = retained ]]
  if output=$(setpriv --reuid="$2" --regid="$3" --clear-groups --no-new-privs -- "$stage/andeiva-preview" grouped-dhcp-state 2>&1); then
    echo ANDEIVA_DHCP_PACKAGE_ACCEPTED_UNPRIVILEGED >&2
    exit 1
  else
    [[ $? == 1 && $output = ANDEIVA_PREVIEW_UNAVAILABLE ]]
  fi
' bash "$stage" "$unprivileged_uid" "$unprivileged_gid"

echo 'PASS packaged state preserves leases and rejects an unprivileged caller'

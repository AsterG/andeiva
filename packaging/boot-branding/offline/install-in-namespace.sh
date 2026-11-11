#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C TZ=UTC DEBIAN_FRONTEND=noninteractive
unset APT_CONFIG BASH_ENV ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH
(( EUID == 0 && $# == 1 )) && [[ "$1" =~ ^[0-9a-f]{64}$ ]] || exit 1
id=$1
bundle="/var/lib/andeiva-boot-bundles/$id"
stage="/var/backups/andeiva-boot-offline/$id"
[[ -d "$stage" && ! -L "$stage" && $(stat -c %u "$stage") = 0 && $(stat -c %a "$stage") = 700 ]]
[[ $(cat "$stage/state") = install-pending && $(readlink /proc/self/ns/mnt) != "$(cat "$stage/parent-namespace")" ]]
marker=/var/backups/andeiva-boot-offline/install-pending
[[ -f "$marker" && ! -L "$marker" && $(stat -c %u "$marker") = 0 && $(stat -c %a "$marker") = 600 && $(cat "$marker") = "$id" ]]
if grep -q ' shared:' /proc/self/mountinfo; then exit 1; fi
[[ $(findmnt -n -o PROPAGATION /) = private ]]
sha256sum -c "$stage/backups.sha256" >/dev/null
sha256sum -c "$stage/status-before.sha256" >/dev/null
[[ $("$bundle/bin/check" verify "$bundle") = "$id" ]]
[[ -f "$stage/deferred-policy.conf" && ! -L "$stage/deferred-policy.conf" && ! -L /etc/initramfs-tools/update-initramfs.conf ]]
mount --bind "$stage/deferred-policy.conf" /etc/initramfs-tools/update-initramfs.conf
mount -o remount,bind,ro /etc/initramfs-tools/update-initramfs.conf
[[ $(grep -cx 'update_initramfs=no' /etc/initramfs-tools/update-initramfs.conf) = 1 ]]
[[ ,$(findmnt -n -o VFS-OPTIONS --target /etc/initramfs-tools/update-initramfs.conf), = *,ro,* ]]
[[ -f "$stage/apt.conf" && ! -L "$stage/apt.conf" && $(stat -c %u "$stage/apt.conf") = 0 && $(stat -c %a "$stage/apt.conf") = 600 ]]
export APT_CONFIG="$stage/apt.conf"
declare -a packages=()
cache_plan=$("$bundle/bin/check" cache-plan "$bundle")
while IFS=$'\t' read -r _file cache_leaf hash; do
  staged="$stage/archives/$cache_leaf"
  [[ $(sha256sum "$staged" | cut -d ' ' -f 1) = "$hash" ]]
  packages+=("$staged")
done <<< "$cache_plan"
apt-get --assume-yes --no-download --no-install-recommends --no-remove --no-upgrade install "${packages[@]}"

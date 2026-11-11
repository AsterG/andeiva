#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C TZ=UTC
unset APT_CONFIG BASH_ENV ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH
fail() { printf '%s\n' "$1" >&2; exit 1; }
(( EUID == 0 && $# >= 1 && $# <= 2 )) || fail 'Usage (authorized local root): install.sh inspect | install --recovery-verified'
[[ "$1" = inspect || "$1" = install ]] || fail ANDEIVA_OFFLINE_OPERATION
if [[ "$1" = install ]]; then
  [[ $# == 2 && "$2" = --recovery-verified ]] || fail ANDEIVA_OFFLINE_RECOVERY_ACK_REQUIRED
else
  [[ $# == 1 ]] || fail ANDEIVA_OFFLINE_OPERATION
fi
bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
secure() {
  local name=$1 permissions
  [[ -e "$name" && ! -L "$name" && $(stat -c %u -- "$name") = 0 ]] || fail ANDEIVA_OFFLINE_UNSAFE_PATH
  permissions=$(stat -c %a -- "$name")
  (( (8#$permissions & 022) == 0 )) || fail ANDEIVA_OFFLINE_UNSAFE_PERMISSIONS
}
for directory in /var /var/lib /var/backups /etc /etc/initramfs-tools /boot /var/lib/dpkg /var/lib/andeiva-boot-bundles /usr /usr/bin /usr/share /usr/share/keyrings /usr/bin/sqv /usr/share/keyrings/debian-archive-keyring.pgp; do secure "$directory"; done
[[ -f /usr/share/keyrings/debian-archive-keyring.pgp && -f /usr/bin/sqv && -x /usr/bin/sqv ]] || fail ANDEIVA_OFFLINE_VERIFIER
secure "$bundle"
[[ "$bundle" =~ ^/var/lib/andeiva-boot-bundles/[0-9a-f]{64}$ ]] || fail ANDEIVA_OFFLINE_BUNDLE_LOCATION
secure "$bundle/bin"
secure "$bundle/bin/check"
[[ -x "$bundle/bin/check" ]] || fail ANDEIVA_OFFLINE_VERIFIER
id=$("$bundle/bin/check" verify "$bundle")
[[ "$id" =~ ^[0-9a-f]{64}$ && "$bundle" = "/var/lib/andeiva-boot-bundles/$id" ]] || fail ANDEIVA_OFFLINE_BUNDLE_ID
while IFS= read -r -d '' file; do secure "$file"; done < <(find "$bundle" -print0)
if ! grep -qx 'VERSION_ID="13"' /usr/lib/os-release || ! grep -qx 'ID=debian' /usr/lib/os-release; then fail ANDEIVA_OFFLINE_DEBIAN13_REQUIRED; fi
[[ $(dpkg --print-architecture) = amd64 && -z $(dpkg --print-foreign-architectures) && ! -e /sys/firmware/efi ]] || fail ANDEIVA_OFFLINE_PLATFORM
[[ $(findmnt -n -o FSTYPE /) = ext4 && $(findmnt -n -o TARGET --target /boot) = / && $(findmnt -n -o TARGET --target /etc) = / && $(findmnt -n -o TARGET --target /usr) = / && $(findmnt -n -o TARGET --target /var/backups) = / ]] || fail ANDEIVA_OFFLINE_LAYOUT
[[ $(df -B1 --output=avail /boot | tail -n1 | tr -d ' ') -gt 1073741824 && $(df --output=iavail /boot | tail -n1 | tr -d ' ') -gt 4096 ]] || fail ANDEIVA_OFFLINE_CAPACITY
boot_bytes=$(du -sb /boot | cut -f1)
bundle_bytes=$(du -sb "$bundle" | cut -f1)
[[ "$boot_bytes" =~ ^[0-9]{1,11}$ && "$bundle_bytes" =~ ^[0-9]{1,10}$ ]] || fail ANDEIVA_OFFLINE_CAPACITY
(( $(df -B1 --output=avail /boot | tail -n1 | tr -d ' ') > 2*boot_bytes + 2*bundle_bytes + 1073741824 )) || fail ANDEIVA_OFFLINE_CAPACITY
[[ -z $(dpkg --audit) && -z $(find /var/lib/dpkg/updates -type f ! -name tmp.i -print -quit) ]] || fail ANDEIVA_OFFLINE_DPKG_UNHEALTHY
"$bundle/bin/check" baseline /var/lib/dpkg || fail ANDEIVA_OFFLINE_BASELINE_REQUIRED
secure /etc/initramfs-tools/update-initramfs.conf
[[ -f /etc/initramfs-tools/update-initramfs.conf && $(grep -c '^update_initramfs=' /etc/initramfs-tools/update-initramfs.conf) = 1 && $(grep -cx 'update_initramfs=yes' /etc/initramfs-tools/update-initramfs.conf) = 1 ]] || fail ANDEIVA_OFFLINE_INITRAMFS_POLICY
[[ ! -L /var/backups/andeiva-boot-branding ]]
if [[ ! -e /var/backups/andeiva-boot-branding ]]; then mkdir -m 0700 -- /var/backups/andeiva-boot-branding; fi
secure /var/backups/andeiva-boot-branding
[[ $(stat -c %a /var/backups/andeiva-boot-branding) = 700 && ! -L /var/backups/andeiva-boot-branding/lock ]] || fail ANDEIVA_OFFLINE_ACTIVATION_LOCK
exec 8>>/var/backups/andeiva-boot-branding/lock
flock -n 8 || fail ANDEIVA_OFFLINE_BUSY
[[ ! -L /var/backups/andeiva-boot-offline ]]
if [[ ! -e /var/backups/andeiva-boot-offline ]]; then mkdir -m 0700 -- /var/backups/andeiva-boot-offline; fi
secure /var/backups/andeiva-boot-offline
[[ $(stat -c %a /var/backups/andeiva-boot-offline) = 700 && ! -L /var/backups/andeiva-boot-offline/lock ]] || fail ANDEIVA_OFFLINE_BACKUP_DIRECTORY
exec 9>>/var/backups/andeiva-boot-offline/lock
flock -n 9 || fail ANDEIVA_OFFLINE_BUSY
marker=/var/backups/andeiva-boot-offline/install-pending
[[ ! -e "$marker" && ! -L "$marker" ]] || fail ANDEIVA_OFFLINE_RECOVERY_REQUIRED
if [[ -e /usr/sbin/andeiva-boot-activation || -L /usr/sbin/andeiva-boot-activation ]]; then
  secure /usr/sbin/andeiva-boot-activation
  [[ -f /usr/sbin/andeiva-boot-activation && -x /usr/sbin/andeiva-boot-activation ]] || fail ANDEIVA_OFFLINE_ACTIVATOR
  timeout --kill-after=1s 5s /usr/sbin/andeiva-boot-activation capabilities | "$bundle/bin/check" capabilities "$bundle" || fail ANDEIVA_OFFLINE_OLD_ACTIVATOR
elif dpkg-query -W -f='${db:Status-Status}' andeiva-boot-activation 2>/dev/null | grep -qx installed; then
  fail ANDEIVA_OFFLINE_ACTIVATOR_MISSING
fi
stage="/var/backups/andeiva-boot-offline/$id"
all_installed=true
while IFS=$'\t' read -r file _origin name version arch _hash; do
  actual=$(dpkg-deb --show --showformat="\${Package}\t\${Version}\t\${Architecture}" "$bundle/$file")
  [[ "$actual" = "$name"$'\t'"$version"$'\t'"$arch" ]] || fail ANDEIVA_OFFLINE_PACKAGE_METADATA
  installed=$(dpkg-query -W -f='${db:Status-Status}\t${Version}\t${Architecture}' "$name" 2>/dev/null || true)
  if [[ "$installed" = installed$'\t'* ]]; then
    [[ "$installed" = installed$'\t'"$version"$'\t'"$arch" ]] || fail ANDEIVA_OFFLINE_UPGRADE_FORBIDDEN
  else
    all_installed=false
  fi
done < <(tail -n +2 "$bundle/manifest.tsv")
if $all_installed; then printf '%s\n' ANDEIVA_OFFLINE_ALREADY_INSTALLED; exit 0; fi
if [[ "$1" = inspect ]]; then
  stage=$(mktemp -d /var/backups/andeiva-boot-offline/.inspect.XXXXXXXX)
  cleanup_inspection() {
    case "$stage" in /var/backups/andeiva-boot-offline/.inspect.*) rm -rf -- "$stage" ;; *) exit 1 ;; esac
  }
  trap cleanup_inspection EXIT
else
  [[ ! -e "$stage" && ! -L "$stage" ]] || fail ANDEIVA_OFFLINE_PENDING_OR_PRIOR_STATE
  mkdir -m 0700 -- "$stage"
fi
install -m 0600 "$bundle/manifest.tsv" "$stage/"
install -d -m 0700 "$stage/archives" "$stage/empty-lists/partial" "$stage/apt-empty" "$stage/apt-log"
cache_plan=$("$bundle/bin/check" cache-plan "$bundle")
while IFS=$'\t' read -r file cache_leaf hash; do
  install -m 0600 "$bundle/$file" "$stage/archives/$cache_leaf"
  [[ $(sha256sum "$stage/archives/$cache_leaf" | cut -d ' ' -f1) = "$hash" ]] || fail ANDEIVA_OFFLINE_CACHE_HASH
done <<< "$cache_plan"
cat > "$stage/apt.conf" <<EOF
Dir::Etc "$stage/apt-empty";
Dir::Etc::main "/dev/null";
Dir::Etc::parts "$stage/apt-empty";
Dir::Etc::sourcelist "/dev/null";
Dir::Etc::sourceparts "$stage/apt-empty";
Dir::Etc::preferences "/dev/null";
Dir::Etc::preferencesparts "$stage/apt-empty";
Dir::State::status "/var/lib/dpkg/status";
Dir::State::lists "$stage/empty-lists";
Dir::Cache::archives "$stage/archives/";
Dir::Log "$stage/apt-log";
Dir::Log::Terminal "/dev/null";
APT::Architecture "amd64";
APT::Architectures { "amd64"; };
DPkg::Lock::Timeout "0";
EOF
chmod 0600 "$stage/apt.conf"
export APT_CONFIG="$stage/apt.conf"
(set -o noclobber; : > "$stage/simulation.log") || fail ANDEIVA_OFFLINE_LOG_EXISTS
sync -f "$stage/simulation.log"
if timeout --kill-after=10s 600s /bin/bash "$bundle/capture.sh" simulate "${stage##*/}"; then
  sync -f "$stage/simulation.log"
else
  sync -f "$stage/simulation.log"
  fail ANDEIVA_OFFLINE_SIMULATION_FAILED
fi
"$bundle/bin/check" plan "$bundle" < "$stage/simulation.log"
[[ "$1" = install ]] || { printf '%s\n' ANDEIVA_OFFLINE_INSPECTION_ONLY; exit 0; }
[[ -s /boot/initrd.img-$(uname -r) && -s /boot/vmlinuz-$(uname -r) ]]
mapfile -t kernels < <(find /boot -maxdepth 1 -type f \( -name 'initrd.img-*' -o -name 'vmlinuz-*' \) -print | sort)
(( ${#kernels[@]} >= 4 )) || fail ANDEIVA_OFFLINE_RECOVERY_KERNEL_REQUIRED
kernel_pairs=0
for file in "${kernels[@]}"; do
  leaf=${file##*/}
  if [[ "$leaf" = initrd.img-* ]]; then
    kernel=${leaf#initrd.img-}
    [[ "$kernel" =~ ^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$ && -f "/boot/vmlinuz-$kernel" && ! -L "/boot/vmlinuz-$kernel" ]] || fail ANDEIVA_OFFLINE_RECOVERY_KERNEL_REQUIRED
    kernel_pairs=$((kernel_pairs+1))
  fi
done
(( kernel_pairs >= 2 )) || fail ANDEIVA_OFFLINE_RECOVERY_KERNEL_REQUIRED
for file in "${kernels[@]}" /etc/default/grub /boot/grub/grub.cfg; do secure "$file"; done
sha256sum "${kernels[@]}" /etc/default/grub /boot/grub/grub.cfg > "$stage/boot-before.sha256"
printf '%s\n' "${kernels[@]}" > "$stage/kernels-before.list"
cp -a /etc/initramfs-tools/update-initramfs.conf "$stage/policy-before.conf"
cp -a /var/lib/dpkg/status "$stage/status-before"
backup_paths=(/boot /etc/default/grub /etc/grub.d /etc/initramfs-tools /var/lib/dpkg/status)
if [[ -e /etc/default/grub.d || -L /etc/default/grub.d ]]; then
  secure /etc/default/grub.d
  [[ -d /etc/default/grub.d ]] || fail ANDEIVA_OFFLINE_LAYOUT
  backup_paths+=(/etc/default/grub.d)
fi
tar --one-file-system --numeric-owner --acls --xattrs -cpf "$stage/boot-before.tar" "${backup_paths[@]}"
sha256sum "$stage/boot-before.tar" "$stage/status-before" "$stage/policy-before.conf" > "$stage/backups.sha256"
sed 's/^update_initramfs=yes$/update_initramfs=no/' "$stage/policy-before.conf" > "$stage/deferred-policy.conf"
chmod 0600 "$stage/deferred-policy.conf"
readlink /proc/self/ns/mnt > "$stage/parent-namespace"
sha256sum /var/lib/dpkg/status > "$stage/status-before.sha256"
printf '%s\n' prepared > "$stage/state"
(set -o noclobber; : > "$stage/install.log") || fail ANDEIVA_OFFLINE_LOG_EXISTS
sync -f "$stage/install.log"
sync -f "$stage"
printf '%s\n' install-pending > "$stage/state"
sync -f "$stage"
# A persistent marker survives parent/namespace death and blocks new activation.
(set -o noclobber; printf '%s\n' "$id" > "$marker") || fail ANDEIVA_OFFLINE_RECOVERY_REQUIRED
chmod 0600 "$marker"
sync -f "$marker"
sync -f /var/backups/andeiva-boot-offline
if timeout --kill-after=10s 600s /bin/bash "$bundle/capture.sh" install "$id"; then
  sync -f "$stage/install.log"
else
  sync -f "$stage/install.log"
  fail ANDEIVA_OFFLINE_INSTALL_FAILED
fi
cmp /etc/initramfs-tools/update-initramfs.conf "$stage/policy-before.conf"
sha256sum -c "$stage/boot-before.sha256" > "$stage/boot-after.log"
find /boot -maxdepth 1 -type f \( -name 'initrd.img-*' -o -name 'vmlinuz-*' \) -print | sort > "$stage/kernels-after.list"
cmp "$stage/kernels-before.list" "$stage/kernels-after.list"
[[ -z $(dpkg --audit) ]] || fail ANDEIVA_OFFLINE_DPKG_UNHEALTHY
while IFS=$'\t' read -r _file _origin name version arch _hash; do
  [[ $(dpkg-query -W -f='${db:Status-Status}\t${Version}\t${Architecture}' "$name") = installed$'\t'"$version"$'\t'"$arch" ]] || fail ANDEIVA_OFFLINE_PACKAGE_POSTCHECK
done < <(tail -n +2 "$bundle/manifest.tsv")
timeout --kill-after=1s 5s /usr/sbin/andeiva-boot-activation capabilities | "$bundle/bin/check" capabilities "$bundle" || fail ANDEIVA_OFFLINE_ACTIVATOR_POSTCHECK
printf '%s\n' installed-boot-unchanged > "$stage/state"
sync -f "$stage"
[[ ! -L "$marker" && $(stat -c %u "$marker") = 0 && $(stat -c %a "$marker") = 600 && $(cat "$marker") = "$id" ]] || fail ANDEIVA_OFFLINE_RECOVERY_REQUIRED
rm -- "$marker"
sync -f /var/backups/andeiva-boot-offline
printf '%s\n' ANDEIVA_OFFLINE_INSTALLED_NO_ACTIVATION

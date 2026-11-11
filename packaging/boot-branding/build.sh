#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022
fail() { printf '%s\n' "$1" >&2; exit 1; }
(( $# == 3 )) || fail 'Usage: build.sh VERSION OUTPUT_DIRECTORY SOURCE_DATE_EPOCH'
(( EUID != 0 )) || fail ANDEIVA_BUILD_REQUIRES_NONROOT
[[ $(uname -s) = Linux ]] || fail ANDEIVA_BUILD_REQUIRES_LINUX
version=$1
epoch=$3
[[ "$version" =~ ^0\.1\.0~alpha[1-9][0-9]{0,5}$ ]] || fail ANDEIVA_BOOT_VERSION
[[ "$epoch" =~ ^[0-9]{1,10}$ ]] || fail ANDEIVA_BOOT_EPOCH
for tool in go dpkg-deb realpath mktemp install find sort xargs sha256sum md5sum touch sed cut awk flock ln; do
  command -v "$tool" >/dev/null || fail "ANDEIVA_BOOT_TOOL_MISSING: $tool"
done
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd -- "$source_dir/../.." && pwd -P)
export GOENV=off GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off GOPROXY=off GOSUMDB=off
[[ $(go env GOVERSION) = "go$(awk '$1 == "go" {print $2}' "$repo/go.mod")" ]] || fail ANDEIVA_BOOT_TOOLCHAIN_MISMATCH
logo="$repo/frontend/public/andeiva-logo.png"
approved=1f79f5ec7f33327c9285c702b63fc5c5a618a28395b2161d594001fdb0199f81
[[ -f "$logo" && ! -L "$logo" ]] || fail ANDEIVA_BOOT_LOGO_SOURCE
[[ $(sha256sum "$logo" | cut -d ' ' -f 1) = "$approved" ]] || fail ANDEIVA_BOOT_LOGO_INTEGRITY
out=$(realpath -m -- "$2")
[[ "$out" != / && "$out" != "$repo" ]] || fail ANDEIVA_BOOT_OUTPUT
mkdir -p -- "$out"
[[ ! -L "$out/.andeiva-boot-build.lock" ]] || fail ANDEIVA_BOOT_OUTPUT_LOCK
exec {output_lock}>> "$out/.andeiva-boot-build.lock"
flock -n "$output_lock" || fail ANDEIVA_BOOT_OUTPUT_BUSY
name="andeiva-boot-branding_${version}_all.deb"
for file in "$name" SHA256SUMS; do
  [[ ! -e "$out/$file" && ! -L "$out/$file" ]] || fail ANDEIVA_BOOT_OUTPUT_EXISTS
done
stage=$(mktemp -d "$out/.andeiva-boot-build.XXXXXXXX")
cleanup() { case "$stage" in "$out"/.andeiva-boot-build.*) rm -rf -- "$stage" ;; *) fail ANDEIVA_BOOT_CLEANUP_REFUSED ;; esac; }
trap cleanup EXIT
export SOURCE_DATE_EPOCH=$epoch
root="$stage/package"
grub="$root/usr/share/grub/themes/andeiva"
plymouth="$root/usr/share/plymouth/themes/andeiva"
doc="$root/usr/share/doc/andeiva-boot-branding"
install -d "$root/DEBIAN" "$grub" "$plymouth" "$doc/docs" "$stage/assets"
go run -mod=readonly -trimpath "$source_dir/render/main.go" "$stage/assets"
install -m 0644 "$logo" "$grub/andeiva-logo.png"
install -m 0644 "$logo" "$plymouth/andeiva-logo.png"
install -m 0644 "$stage/assets/background.png" "$grub/"
install -m 0644 "$stage/assets/"*.png "$plymouth/"
install -m 0644 "$source_dir/grub/theme.txt" "$grub/"
install -m 0644 "$source_dir/plymouth/andeiva.plymouth" "$source_dir/plymouth/andeiva.script" "$plymouth/"
install -m 0644 "$repo/LICENSE" "$repo/NOTICE" "$source_dir/README.md" "$source_dir/DESIGN.md" "$doc/"
install -m 0644 "$source_dir/docs/"*.md "$doc/docs/"
sed "s/@VERSION@/$version/g" "$source_dir/control" > "$root/DEBIAN/control"
chmod 0755 "$root/DEBIAN"
(cd "$root" && find usr -type f -print0 | sort -z | xargs -0 md5sum > DEBIAN/md5sums)
find "$root" -exec touch --no-dereference --date="@$epoch" {} +
dpkg-deb --root-owner-group --build --uniform-compression -Zxz "$root" "$stage/$name"
(cd "$stage" && sha256sum "$name" > SHA256SUMS)
# Same-filesystem links publish complete files and refuse an existing destination.
ln -T -- "$stage/$name" "$out/$name"
ln -T -- "$stage/SHA256SUMS" "$out/SHA256SUMS"
printf 'Built inactive theme resources: %s\n' "$name"

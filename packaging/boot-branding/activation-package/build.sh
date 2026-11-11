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
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd -- "$here/../../.." && pwd -P)
out=$(realpath -m -- "$2")
[[ "$out" != / && "$out" != "$repo" ]] || fail ANDEIVA_BOOT_OUTPUT
mkdir -p -- "$out"
[[ ! -L "$out/.activation-build.lock" ]] || fail ANDEIVA_BOOT_OUTPUT_LOCK
exec {output_lock}>> "$out/.activation-build.lock"
flock -n "$output_lock" || fail ANDEIVA_BOOT_OUTPUT_BUSY
name="andeiva-boot-activation_${version}_amd64.deb"
for file in "$name" SHA256SUMS; do
  [[ ! -e "$out/$file" && ! -L "$out/$file" ]] || fail ANDEIVA_BOOT_OUTPUT_EXISTS
done
stage=$(mktemp -d "$out/.activation-build.XXXXXXXX")
cleanup() {
  case "$stage" in "$out"/.activation-build.*) rm -rf -- "$stage" ;; *) fail ANDEIVA_BOOT_CLEANUP_REFUSED ;; esac
}
trap cleanup EXIT
export SOURCE_DATE_EPOCH=$epoch GOENV=off GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off GOPROXY=off GOSUMDB=off
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
[[ $(go env GOVERSION) = "go$(awk '$1 == "go" {print $2}' "$repo/go.mod")" ]] || fail ANDEIVA_BOOT_TOOLCHAIN_MISMATCH
root="$stage/package"
doc="$root/usr/share/doc/andeiva-boot-activation"
install -d "$root/DEBIAN" "$root/usr/sbin" "$doc/docs"
(cd "$repo" && go build -mod=readonly -trimpath -buildvcs=false -o "$root/usr/sbin/andeiva-boot-activation" ./packaging/boot-branding/activation)
install -m 0644 "$repo/LICENSE" "$repo/NOTICE" "$here/../activation/DESIGN.md" "$doc/"
install -m 0644 "$(go env GOROOT)/LICENSE" "$doc/GO_LICENSE"
install -m 0644 "$here/../activation/docs/"*.md "$doc/docs/"
sed "s/@VERSION@/$version/g" "$here/control" > "$root/DEBIAN/control"
chmod 0755 "$root/DEBIAN" "$root/usr/sbin/andeiva-boot-activation"
(cd "$root" && find usr -type f -print0 | sort -z | xargs -0 md5sum > DEBIAN/md5sums)
find "$root" -exec touch --no-dereference --date="@$epoch" {} +
dpkg-deb --root-owner-group --build --uniform-compression -Zxz "$root" "$stage/$name"
(cd "$stage" && sha256sum "$name" > SHA256SUMS)
ln -T -- "$stage/$name" "$out/$name"
ln -T -- "$stage/SHA256SUMS" "$out/SHA256SUMS"
printf 'Built inactive local activation tool: %s\n' "$name"

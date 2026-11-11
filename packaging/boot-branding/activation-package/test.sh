#!/usr/bin/env bash
set -euo pipefail
(( EUID != 0 )) || { echo ANDEIVA_TEST_REQUIRES_NONROOT >&2; exit 1; }
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
version=0.1.0~alpha901
for output in first second; do
  bash "$here/build.sh" "$version" "$stage/$output" 1700000000
done
name="andeiva-boot-activation_${version}_amd64.deb"
cmp "$stage/first/$name" "$stage/second/$name"
pkg="$stage/first/$name"
[[ $(dpkg-deb -f "$pkg" Package) = andeiva-boot-activation ]]
[[ $(dpkg-deb -f "$pkg" Architecture) = amd64 ]]
[[ $(dpkg-deb -f "$pkg" Version) = "$version" ]]
[[ $(dpkg-deb -f "$pkg" X-Andeiva-Offline-Install-Guard) = 1 ]]
dpkg-deb --ctrl-tarfile "$pkg" | tar -tf - | LC_ALL=C sort > "$stage/control-files"
printf '%s\n' ./ ./control ./md5sums > "$stage/expected-control-files"
cmp "$stage/control-files" "$stage/expected-control-files"
# Inspect names without extracting archive paths or running package scripts.
dpkg-deb --fsys-tarfile "$pkg" | tar -tf - > "$stage/data-files"
grep -Fx './usr/sbin/andeiva-boot-activation' "$stage/data-files"
dpkg-deb --fsys-tarfile "$pkg" | tar -xOf - ./usr/share/doc/andeiva-boot-activation/GO_LICENSE > "$stage/go-license"
cmp "$stage/go-license" "$(go env GOROOT)/LICENSE"
[[ $(grep -c '\.md$' "$stage/data-files") = 4 ]]
! grep -Eq '^\./(etc|boot|var)/|/systemd/|/init\.d/' "$stage/data-files"
[[ $(stat -c %s "$pkg") -lt 8388608 ]]
printf '%s\n' ANDEIVA_BOOT_ACTIVATION_PACKAGE_OK

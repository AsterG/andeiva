#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022
fail() { printf '%s\n' "$1" >&2; exit 1; }
(( $# >= 2 && $# <= 3 )) || fail 'Usage: build.sh VERSION OUTPUT_DIRECTORY [SOURCE_DATE_EPOCH]'
version=$1
(( ${#version} <= 64 )) || fail ANDEIVA_PREVIEW_VERSION
[[ "$version" =~ ^0\.1\.0~alpha[1-9][0-9]*$ ]] || fail ANDEIVA_PREVIEW_VERSION
(( EUID != 0 )) || fail ANDEIVA_BUILD_REQUIRES_NONROOT
[[ $(uname -s) = Linux ]] || fail ANDEIVA_BUILD_REQUIRES_LINUX
for tool in go node npm git dpkg-deb realpath mktemp install find sort xargs sha256sum md5sum touch sed awk tar; do
  command -v "$tool" >/dev/null || fail "ANDEIVA_BUILD_TOOL_MISSING: $tool"
done
templates=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd -- "$templates/../.." && pwd -P)
out=$(realpath -m -- "$2")
[[ "$out" != / && "$out" != "$repo" ]] || fail ANDEIVA_INVALID_OUTPUT_DIRECTORY
mkdir -p -- "$out"
name="andeiva-firewall-preview_${version}_amd64.deb"
for file in "$name" SHA256SUMS build-info.txt; do
  [[ ! -e "$out/$file" && ! -L "$out/$file" ]] || fail ANDEIVA_OUTPUT_ALREADY_EXISTS
done
epoch=${3:-${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct)}}
[[ "$epoch" =~ ^[0-9]{1,10}$ ]] || fail ANDEIVA_SOURCE_DATE_EPOCH
export SOURCE_DATE_EPOCH=$epoch GOENV=off GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off
module_cache=${GOMODCACHE:-$(go env GOMODCACHE)}
module_cache=$(realpath -e -- "$module_cache") || fail ANDEIVA_MODULE_CACHE_REQUIRED
[[ -d "$module_cache" ]] || fail ANDEIVA_MODULE_CACHE_REQUIRED
export GOMODCACHE="$module_cache" GOPROXY=off GOSUMDB=off GOPRIVATE= GONOPROXY= GONOSUMDB=
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
stage=$(mktemp -d "$out/.andeiva-preview-build.XXXXXXXX")
cleanup() { case "$stage" in "$out"/.andeiva-preview-build.*) rm -rf -- "$stage" ;; *) fail ANDEIVA_CLEANUP_REFUSED ;; esac; }
trap cleanup EXIT
cd -- "$repo"
[[ $(go env GOVERSION) = "go$(awk '$1 == "go" {print $2}' go.mod)" ]] || fail ANDEIVA_TOOLCHAIN_MISMATCH
go mod verify
go list -mod=readonly -m -f '{"path":"{{.Path}}","version":"{{.Version}}","main":{{.Main}}}' all > "$stage/go-inventory.jsonl"
[[ $(node --version) = v24.20.0 ]] || fail ANDEIVA_NODE_TOOLCHAIN_MISMATCH
[[ -d frontend/node_modules ]] || fail ANDEIVA_FRONTEND_DEPENDENCIES_REQUIRED
(cd frontend && npm run build)
root="$stage/package"
install -d "$root/DEBIAN" "$root/usr/bin" "$root/usr/lib/andeiva-preview" \
  "$root/usr/lib/systemd/system" "$root/etc/andeiva-preview" "$root/usr/share/andeiva-preview/web" \
  "$root/usr/share/doc/andeiva-firewall-preview"
identity="-X github.com/AsterG/andeiva/internal/productinfo.Version=$version"
go build -mod=readonly -trimpath -buildvcs=false -ldflags "$identity" -o "$root/usr/lib/andeiva-preview/andeiva-preview" ./cmd/andeiva-preview
go build -mod=readonly -trimpath -buildvcs=false -ldflags "$identity" -o "$root/usr/bin/andeiva" ./cmd/andeiva
cp -a frontend/dist/. "$root/usr/share/andeiva-preview/web/"
find "$root/usr/share/andeiva-preview/web" -type d -exec chmod 0755 {} +
find "$root/usr/share/andeiva-preview/web" -type f -exec chmod 0644 {} +
for unit in "$templates"/*.service "$templates"/*.socket "$templates"/*.target; do install -m 0644 "$unit" "$root/usr/lib/systemd/system/"; done
install -m 0644 "$templates/config.json.example" "$root/etc/andeiva-preview/"
for script in preinst postinst prerm postrm; do install -m 0755 "$templates/$script" "$root/DEBIAN/$script"; done
sed "s/@VERSION@/$version/g" "$templates/control" > "$root/DEBIAN/control"
doc="$root/usr/share/doc/andeiva-firewall-preview"
install -m 0644 LICENSE NOTICE "$templates/README.md" "$doc/"
install -m 0644 "$(go env GOROOT)/LICENSE" "$doc/LICENSE.Go"
cp -a "$templates/docs" "$doc/"
install -d "$doc/tests"
install -m 0755 "$templates/tests/native.sh" "$doc/tests/native.sh"
install -d "$doc/firewalladmin/docs"
install -d "$doc/console"
install -m 0644 internal/firewalladmin/VALIDATION.md internal/firewalladmin/TRAFFIC.md internal/firewalladmin/MILESTONE.md "$doc/firewalladmin/"
for language in en es pt; do
  install -m 0644 "internal/firewalladmin/docs/$language.md" "$doc/firewalladmin/docs/"
  install -m 0644 "frontend/docs/console-$language.md" "$doc/console/$language.md"
  sed -i 's|../../../internal/firewalladmin/docs/|../firewalladmin/docs/|g' "$doc/docs/$language.md"
  sed -i 's|../../../frontend/docs/console-|../console/|g' "$doc/docs/$language.md"
  sed -i 's|\.\./\.\./packaging/preview/docs/|../docs/|g' "$doc/console/$language.md"
done
install -d "$doc/dependencies"
node scripts/check-licenses.mjs > "$doc/dependencies/npm-inventory.json"
for dependency in react react-dom scheduler; do
  install -m 0644 "frontend/node_modules/$dependency/LICENSE" "$doc/dependencies/LICENSE.$dependency"
done
install -m 0644 go.mod go.sum packaging/licenses/golang-x-LICENSE.txt packaging/licenses/golang-x-PATENTS.txt "$doc/dependencies/"
install -m 0644 "$stage/go-inventory.jsonl" "$doc/dependencies/"
(cd "$doc/dependencies" && sha256sum go.mod go.sum golang-x-LICENSE.txt golang-x-PATENTS.txt go-inventory.jsonl > SHA256SUMS)
printf 'version=%s\nsource_revision=%s\nsource_date_epoch=%s\ngo=%s\nnode=%s\n' \
  "$version" "$(git rev-parse HEAD)" "$epoch" "$(go env GOVERSION)" "$(node --version)" > "$out/build-info.txt"
install -m 0644 "$out/build-info.txt" "$doc/build-info.txt"
(cd "$root" && find usr etc -type f -print0 | sort -z | xargs -0 md5sum > DEBIAN/md5sums)
find "$root" -exec touch --no-dereference --date="@$epoch" {} +
dpkg-deb --root-owner-group --build --uniform-compression -Zxz "$root" "$out/$name"
(cd "$out" && sha256sum "$name" build-info.txt > SHA256SUMS)
printf 'Built %s\n' "$name"

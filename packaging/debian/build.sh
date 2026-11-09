#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

if (( $# < 2 || $# > 3 )); then
  printf '%s\n' 'Usage: bash packaging/debian/build.sh VERSION OUT_DIR [SOURCE_DATE_EPOCH]' >&2
  exit 2
fi
version=$1
[[ "$version" =~ ^0\.0\.0~exp[1-9][0-9]*$ ]] || fail ANDEIVA_INVALID_EXPERIMENTAL_VERSION
(( EUID != 0 )) || fail ANDEIVA_BUILD_REQUIRES_NONROOT
[[ "$(uname -s)" = Linux ]] || fail ANDEIVA_BUILD_REQUIRES_LINUX
for tool in go dpkg dpkg-deb git realpath mktemp install find sort xargs sha256sum md5sum touch sed awk ln cut cat chmod mkdir rm uname; do
  command -v "$tool" >/dev/null || fail "ANDEIVA_BUILD_TOOL_MISSING: $tool"
done
dpkg --validate-version "$version"

template_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd -- "$template_dir/../.." && pwd -P)
source_revision=$(git -C "$repo" rev-parse --verify HEAD 2>/dev/null || printf unknown)
epoch=${3:-${SOURCE_DATE_EPOCH:-}}
if [[ -z "$epoch" ]]; then
  epoch=$(git -C "$repo" log -1 --format=%ct) || fail ANDEIVA_SOURCE_DATE_EPOCH_REQUIRED
fi
[[ "$epoch" =~ ^[0-9]{1,10}$ ]] || fail ANDEIVA_INVALID_SOURCE_DATE_EPOCH
epoch=$((10#$epoch))
export SOURCE_DATE_EPOCH=$epoch

out_dir=$(realpath -m -- "$2")
[[ "$out_dir" != / && "$out_dir" != "$repo" ]] || fail ANDEIVA_INVALID_OUTPUT_DIRECTORY
mkdir -p -- "$out_dir"
package_name="andeiva-experimental_${version}_amd64.deb"
for output in "$package_name" SHA256SUMS build-info.txt; do
  [[ ! -e "$out_dir/$output" && ! -L "$out_dir/$output" ]] || fail ANDEIVA_OUTPUT_ALREADY_EXISTS
done
stage=$(mktemp -d "$out_dir/.andeiva-build.XXXXXXXX")
cleanup() {
  case "$stage" in
    "$out_dir"/.andeiva-build.*) rm -rf -- "$stage" ;;
    *) printf '%s\n' 'ANDEIVA_BUILD_CLEANUP_REFUSED' >&2 ;;
  esac
}
trap cleanup EXIT

# Build from local source and the installed toolchain only; never fetch dependencies.
export GOENV=off GOTOOLCHAIN=local GOPROXY=off GOWORK=off GOTELEMETRY=off
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
export GOCACHE="$stage/cache/go-build"
export GOMODCACHE="$stage/cache/go-mod"
export GOPATH="$stage/cache/go-path"
export XDG_CONFIG_HOME="$stage/cache/config"
mkdir -p "$GOCACHE" "$GOMODCACHE" "$GOPATH" "$XDG_CONFIG_HOME"
cd -- "$repo"
go_version=$(go env GOVERSION)
required_version=$(awk '$1 == "go" { print $2 }' go.mod)
[[ "$go_version" = "go$required_version" ]] || fail ANDEIVA_BUILD_TOOLCHAIN_MISMATCH
[[ "$(go list -m all)" = github.com/AsterG/andeiva ]] || fail ANDEIVA_EXTERNAL_DEPENDENCIES_NOT_SUPPORTED
go_root=$(go env GOROOT)
[[ -r "$go_root/LICENSE" ]] || fail ANDEIVA_GO_LICENSE_MISSING

templates=(build.sh control conffiles preinst postinst prerm postrm andeiva-api.service andeiva-api.env wait-ready copyright)
source_hash=$(
  {
    printf '%s\0' go.mod LICENSE NOTICE
    find cmd internal -type f -name '*.go' -print0
    for file in "${templates[@]}"; do printf 'packaging/debian/%s\0' "$file"; done
  } | sort -z | xargs -0 sha256sum -- | sha256sum | cut -d ' ' -f 1
)

package_root="$stage/package"
doc_dir="$package_root/usr/share/doc/andeiva-experimental"
install -d -m 0755 "$package_root/DEBIAN" "$package_root/usr/bin" \
  "$package_root/usr/lib/andeiva" "$package_root/usr/lib/systemd/system" \
  "$package_root/etc/andeiva" "$doc_dir"
go build -trimpath -buildvcs=false -o "$package_root/usr/bin/andeiva" ./cmd/andeiva
go build -trimpath -buildvcs=false -o "$package_root/usr/lib/andeiva/andeiva-api" ./cmd/andeiva-api
chmod 0755 "$package_root/usr/bin/andeiva" "$package_root/usr/lib/andeiva/andeiva-api"
install -m 0755 "$template_dir/wait-ready" "$package_root/usr/lib/andeiva/wait-ready"
install -m 0644 "$template_dir/andeiva-api.service" "$package_root/usr/lib/systemd/system/andeiva-api.service"
install -m 0644 "$template_dir/andeiva-api.env" "$package_root/etc/andeiva/andeiva-api.env"
install -m 0644 LICENSE "$doc_dir/LICENSE"
install -m 0644 NOTICE "$doc_dir/NOTICE"
install -m 0644 "$go_root/LICENSE" "$doc_dir/LICENSE.Go"
install -m 0644 "$template_dir/copyright" "$doc_dir/copyright"
cat > "$stage/build-info.txt" <<EOF
package=andeiva-experimental
version=$version
architecture=amd64
go_version=$go_version
source_revision=$source_revision
source_content_sha256=$source_hash
source_state=working-tree
source_date_epoch=$epoch
EOF
install -m 0644 "$stage/build-info.txt" "$doc_dir/build-info.txt"
install -m 0644 "$template_dir/conffiles" "$package_root/DEBIAN/conffiles"
for file in preinst postinst prerm postrm; do
  install -m 0755 "$template_dir/$file" "$package_root/DEBIAN/$file"
done
# Logical sizes keep this metadata independent of the build filesystem's blocks.
installed_size=$(find "$package_root" -type f -printf '%s\n' | awk '{total += $1} END {print int((total + 1023) / 1024)}')
sed -e "s/@VERSION@/$version/" -e "s/@INSTALLED_SIZE@/$installed_size/" \
  "$template_dir/control" > "$package_root/DEBIAN/control"
(
  cd -- "$package_root"
  find etc usr -type f -print0 | sort -z | xargs -0 md5sum -- > DEBIAN/md5sums
)
find "$package_root" -print0 | xargs -0 touch --no-dereference --date="@$SOURCE_DATE_EPOCH"
dpkg-deb --root-owner-group --uniform-compression -Zxz -z6 --threads-max=1 \
  --build "$package_root" "$stage/$package_name"
(
  cd -- "$stage"
  sha256sum "$package_name" build-info.txt > SHA256SUMS
)
# Hard links publish without overwriting an existing artifact or following its link.
ln -- "$stage/$package_name" "$out_dir/$package_name"
ln -- "$stage/build-info.txt" "$out_dir/build-info.txt"
ln -- "$stage/SHA256SUMS" "$out_dir/SHA256SUMS"
printf '%s\n' "$out_dir/$package_name"

#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 077
fail() { printf '%s\n' "$1" >&2; exit 1; }
(( EUID != 0 && $# == 4 )) || fail 'Usage (nonroot DEV): build.sh TARGET_DPKG_STATUS PRODUCT_DEB_DIRECTORY OUTPUT_DIRECTORY SOURCE_DATE_EPOCH'
[[ $(uname -s) = Linux && -f /usr/share/keyrings/debian-archive-keyring.pgp && ! -L /usr/share/keyrings/debian-archive-keyring.pgp ]] || fail ANDEIVA_OFFLINE_DEBIAN_DEV_REQUIRED
grep -qx 'VERSION_ID="13"' /usr/lib/os-release || fail ANDEIVA_OFFLINE_DEBIAN13_DEV_REQUIRED
grep -qx 'ID=debian' /usr/lib/os-release || fail ANDEIVA_OFFLINE_DEBIAN13_DEV_REQUIRED
[[ -f "$1" && ! -L "$1" && -d "$2" && "$4" =~ ^(0|[1-9][0-9]{0,9})$ ]] || fail ANDEIVA_OFFLINE_INPUT
(( 10#$4 <= 4294967295 )) || fail ANDEIVA_OFFLINE_INPUT
for tool in apt-get dpkg-deb sqv go realpath mktemp flock install find sort sha256sum cp tar gzip awk cut sed ln chmod; do command -v "$tool" >/dev/null || fail "ANDEIVA_OFFLINE_TOOL: $tool"; done
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd -- "$source_dir/../../.." && pwd -P)
status=$(realpath -e -- "$1")
products=$(realpath -e -- "$2")
out=$(realpath -m -- "$3")
[[ "$out" != / && "$out" != "$repo" ]] || fail ANDEIVA_OFFLINE_OUTPUT
mkdir -p -- "$out"
[[ ! -L "$out/.offline-build.lock" ]] || fail ANDEIVA_OFFLINE_OUTPUT
exec {output_lock}>> "$out/.offline-build.lock"
flock -n "$output_lock" || fail ANDEIVA_OFFLINE_BUSY
scratch=$(mktemp -d /tmp/andeiva-offline-build.XXXXXXXX)
cleanup() { case "$scratch" in /tmp/andeiva-offline-build.*) rm -rf -- "$scratch" ;; *) exit 1 ;; esac; }
trap cleanup EXIT
payload="$scratch/bundle"
install -d "$payload/archives" "$payload/provenance" "$payload/bin" "$payload/docs" "$payload/licenses" "$scratch/apt/etc/apt.conf.d" "$scratch/apt/etc/sources.list.d" "$scratch/apt/state/lists/partial" "$scratch/apt/cache/archives/partial" "$scratch/apt/log"
install -m 0600 "$status" "$scratch/status"
export GOENV=off GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off GOPROXY=off GOSUMDB=off GOFLAGS='' GOEXPERIMENT='' CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
[[ $(go env GOVERSION) = "go$(awk '$1 == "go" {print $2}' "$repo/go.mod")" ]] || fail ANDEIVA_OFFLINE_GO_VERSION
install -m 0644 "$(go env GOROOT)/LICENSE" "$payload/licenses/GO-LICENSE"
(cd "$source_dir" && go build -mod=readonly -trimpath -buildvcs=false -o "$payload/bin/check" ./check)
binary_metadata=$(go version -m "$payload/bin/check")
for setting in CGO_ENABLED=0 GOARCH=amd64 GOOS=linux GOAMD64=v1; do
  printf '%s\n' "$binary_metadata" | grep -Fqx -- $'\tbuild\t'"$setting" || fail ANDEIVA_OFFLINE_BINARY_TARGET
done
"$payload/bin/check" baseline "$scratch" || fail ANDEIVA_OFFLINE_BASELINE_REQUIRED
install -m 0755 "$source_dir/install.sh" "$source_dir/install-in-namespace.sh" "$source_dir/capture.sh" "$payload/"
install -m 0644 "$source_dir/README.md" "$source_dir/DESIGN.md" "$repo/LICENSE" "$repo/NOTICE" "$payload/"
install -m 0644 "$source_dir/docs/"*.md "$payload/docs/"
version=
count=0
declare -a product_inputs=()
for file in "$products"/*.deb; do
  [[ -f "$file" && ! -L "$file" ]] || fail ANDEIVA_OFFLINE_PRODUCT
  name=$(dpkg-deb -f "$file" Package)
  candidate=$(dpkg-deb -f "$file" Version)
  [[ "$name" = andeiva-boot-branding || "$name" = andeiva-boot-activation ]] || fail ANDEIVA_OFFLINE_PRODUCT
  [[ "$candidate" =~ ^0\.1\.0~alpha[1-9][0-9]{0,5}$ ]] || fail ANDEIVA_OFFLINE_PRODUCT_VERSION
  [[ -z "$version" || "$version" = "$candidate" ]] || fail ANDEIVA_OFFLINE_PRODUCT_VERSION
  version=$candidate
  count=$((count+1)); (( count <= 2 )) || fail ANDEIVA_OFFLINE_PRODUCT_COUNT
  printf -v leaf '%04d.deb' "$count"
  install -m 0644 "$file" "$payload/archives/$leaf"
  product_inputs+=("$payload/archives/$leaf")
done
(( count == 2 )) || fail ANDEIVA_OFFLINE_PRODUCT_COUNT
artifact="andeiva-boot-offline_${version}_amd64.tar.gz"
[[ ! -e "$out/$artifact" && ! -L "$out/$artifact" && ! -e "$out/SHA256SUMS" && ! -L "$out/SHA256SUMS" ]] || fail ANDEIVA_OFFLINE_OUTPUT_EXISTS
cat > "$scratch/apt/etc/sources.list" <<'SOURCES'
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.pgp] https://deb.debian.org/debian trixie main
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.pgp] https://deb.debian.org/debian trixie-updates main
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.pgp] https://security.debian.org/debian-security trixie-security main
SOURCES
cat > "$scratch/apt.conf" <<EOF
Dir::Etc "$scratch/apt/etc";
Dir::Etc::main "-";
Dir::Etc::parts "apt.conf.d";
Dir::State "$scratch/apt/state";
Dir::State::status "$scratch/status";
Dir::Cache "$scratch/apt/cache";
Dir::Log "$scratch/apt/log";
APT::Architecture "amd64";
APT::Architectures { "amd64"; };
Acquire::Languages "none";
Acquire::https::Verify-Peer "true";
Acquire::https::Verify-Host "true";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowWeakRepositories "false";
Acquire::Check-Valid-Until "true";
Acquire::Check-Date "true";
APT::Get::AllowUnauthenticated "false";
EOF
export APT_CONFIG="$scratch/apt.conf"
apt-get update > "$scratch/apt-update.log" 2>&1 || fail ANDEIVA_OFFLINE_AUTHENTICATED_UPDATE_FAILED
apt-get -s --no-install-recommends --no-remove --no-upgrade install "${product_inputs[@]}" > "$scratch/simulation.log" 2>&1 || fail ANDEIVA_OFFLINE_CLOSURE_FAILED
if grep -Eq '^(Remv |Purg |Inst [^ ]+ \[)' "$scratch/simulation.log"; then fail ANDEIVA_OFFLINE_UPGRADE_OR_REMOVAL; fi
apt-get --download-only --assume-yes --no-install-recommends --no-remove --no-upgrade install "${product_inputs[@]}" > "$scratch/apt-download.log" 2>&1 || fail ANDEIVA_OFFLINE_CLOSURE_FAILED
for file in "$scratch/apt/cache/archives/"*.deb; do
  [[ -f "$file" ]] || continue
  package_name=$(dpkg-deb -f "$file" Package)
  [[ "$package_name" != andeiva-boot-branding && "$package_name" != andeiva-boot-activation ]] || continue
  count=$((count+1)); (( count <= 128 )) || fail ANDEIVA_OFFLINE_PACKAGE_LIMIT
  printf -v leaf '%04d.deb' "$count"
  install -m 0644 "$file" "$payload/archives/$leaf"
done
for suite in trixie trixie-updates trixie-security; do
  mapfile -t releases < <(find "$scratch/apt/state/lists" -maxdepth 1 -type f -name "*_dists_${suite}_InRelease")
  mapfile -t indexes < <(find "$scratch/apt/state/lists" -maxdepth 1 -type f -name "*_dists_${suite}_main_binary-amd64_Packages*")
  (( ${#releases[@]} == 1 && ${#indexes[@]} == 1 )) || fail ANDEIVA_OFFLINE_METADATA
  install -m 0644 "${releases[0]}" "$payload/provenance/$suite.InRelease"
  /usr/lib/apt/apt-helper cat-file "${indexes[0]}" > "$payload/provenance/$suite.Packages"
done
printf 'ANDEIVA_BOOT_OFFLINE_V1\t%s\t%s\n' "$version" "$4" > "$payload/manifest.tsv"
for file in "$payload/archives/"*.deb; do
  name=$(dpkg-deb -f "$file" Package); candidate=$(dpkg-deb -f "$file" Version); arch=$(dpkg-deb -f "$file" Architecture)
  origin=debian
  [[ "$name" != andeiva-boot-branding && "$name" != andeiva-boot-activation ]] || origin=product
  printf 'archives/%s\t%s\t%s\t%s\t%s\t%s\n' "${file##*/}" "$origin" "$name" "$candidate" "$arch" "$(sha256sum "$file" | cut -d ' ' -f 1)" >> "$payload/manifest.tsv"
done
find "$payload" -type d -exec chmod 0755 {} +
find "$payload" -type f -exec chmod 0644 {} +
chmod 0755 "$payload/install.sh" "$payload/install-in-namespace.sh" "$payload/capture.sh" "$payload/bin/check"
(cd "$payload" && find . -type f -printf '%P\n' | sort | while IFS= read -r file; do sha256sum "$file"; done) > "$scratch/payload-sums"
install -m 0644 "$scratch/payload-sums" "$payload/SHA256SUMS"
"$payload/bin/check" verify "$payload" > "$scratch/bundle-id"
tar --sort=name --mtime="@$4" --owner=0 --group=0 --numeric-owner --format=gnu -C "$payload" -cf - . | gzip -n -9 > "$scratch/$artifact"
(cd "$scratch" && sha256sum "$artifact" > SHA256SUMS)
publication=$(mktemp -d "$out/.offline-publish.XXXXXXXX")
install -m 0644 "$scratch/$artifact" "$scratch/SHA256SUMS" "$publication/"
ln -T -- "$publication/$artifact" "$out/$artifact"
ln -T -- "$publication/SHA256SUMS" "$out/SHA256SUMS"
rm -f -- "$publication/$artifact" "$publication/SHA256SUMS"
rmdir -- "$publication"
printf 'Built %s; inventory ID %s\n' "$artifact" "$(cat "$scratch/bundle-id")"

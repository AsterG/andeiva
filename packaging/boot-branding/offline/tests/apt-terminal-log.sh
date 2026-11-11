#!/usr/bin/env bash
# DEV container only: actual APT/dpkg with a synthetic, deliberately noisy package.
set -euo pipefail
umask 077
[[ $# == 1 && "$1" = --disposable-dev-container && $EUID == 0 && -f /.dockerenv && $(findmnt -n -o FSTYPE /) = overlay ]] || exit 1
for path in /etc /usr /var/lib/dpkg /var/log; do
  [[ $(findmnt -n -o TARGET --target "$path") = / ]] || exit 1
done
[[ $(apt-get --version | head -1) = 'apt 3.0.'* ]] || exit 1
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scratch=$(mktemp -d /tmp/andeiva-apt-noise.XXXXXXXX)
cleanup() {
  case "$scratch" in /tmp/andeiva-apt-noise.*) rm -rf -- "$scratch" ;; *) exit 1 ;; esac
}
trap cleanup EXIT
failure() {
  if [[ -n ${stage:-} && -f "$stage/primary.log" ]]; then head -c 2048 "$stage/primary.log" >&2; fi
}
trap failure ERR
(cd "$source_dir" && go build -mod=readonly -trimpath -buildvcs=false -o "$scratch/check" ./check)
before_null=$(stat -c '%u:%g:%a:%t:%T' /dev/null)
template=$(awk '/^cat > "\$stage\/apt.conf" <<EOF$/ {copy=1;next} copy && /^EOF$/ {exit} copy {print}' "$source_dir/install.sh")
[[ "$template" = *'Dir::Log::Terminal "/dev/null";'* ]]
for mode in default fixed; do
  stage="$scratch/$mode"
  package="andeiva-offline-noise-$mode-fixture"
  mkdir -p "$stage/archives" "$stage/empty-lists/partial" "$stage/apt-empty" "$stage/apt-log" "$stage/package/DEBIAN"
  printf 'Package: %s\nVersion: 1:1\nArchitecture: all\nMaintainer: Fixture\nDescription: Development output fixture\n' "$package" > "$stage/package/DEBIAN/control"
  cat > "$stage/package/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
printf 'NOISE_STDOUT_FIXTURE\n'
printf 'NOISE_STDERR_FIXTURE\n' >&2
dd if=/dev/zero bs=65536 count=80 2>/dev/null | tr '\000' X
exit 0
POSTINST
  chmod 0755 "$stage/package/DEBIAN" "$stage/package/DEBIAN/postinst"
  chmod 0644 "$stage/package/DEBIAN/control"
  archive="$stage/archives/${package}_1%3a1_all.deb"
  dpkg-deb --build --root-owner-group "$stage/package" "$archive" >/dev/null
  configuration=${template//\$stage/$stage}
  if [[ "$mode" = default ]]; then
    configuration=${configuration//'Dir::Log::Terminal "/dev/null";'/'Dir::Log::Terminal "term.log";'}
  fi
  printf '%s\n' "$configuration" > "$stage/apt.conf"
  export APT_CONFIG="$stage/apt.conf" DEBIAN_FRONTEND=noninteractive
  (set -o noclobber; : > "$stage/primary.log")
  sync -f "$stage/primary.log"
  trap - ERR
  set +e
  apt-get --assume-yes --no-download --no-install-recommends --no-upgrade --no-remove install "$archive" 2>&1 | "$scratch/check" bounded-log "$stage" >> "$stage/primary.log" 2> "$stage/logger-error"
  statuses=("${PIPESTATUS[@]}")
  set -e
  trap failure ERR
  (( statuses[0] == 0 && statuses[1] != 0 ))
  [[ $(stat -c %s "$stage/primary.log") -le 4194304 ]]
  grep -q NOISE_STDOUT_FIXTURE "$stage/primary.log"
  grep -q NOISE_STDERR_FIXTURE "$stage/primary.log"
  tail -n1 "$stage/primary.log" | grep -qx ANDEIVA_OFFLINE_LOG_TRUNCATED
  grep -q "$package" "$stage/apt-log/history.log"
  grep -q "$package" /var/log/dpkg.log
  if [[ "$mode" = default ]]; then
    [[ -f "$stage/apt-log/term.log" && $(stat -c %s "$stage/apt-log/term.log") -gt 4194304 ]]
    printf 'APT duplicate terminal log reproduced: %s bytes\n' "$(stat -c %s "$stage/apt-log/term.log")"
  else
    [[ ! -e "$stage/apt-log/term.log" ]]
    printf 'APT terminal duplicate absent; primary=%s bytes; history and dpkg audit retained\n' "$(stat -c %s "$stage/primary.log")"
  fi
done
[[ $(stat -c '%u:%g:%a:%t:%T' /dev/null) = "$before_null" ]]
printf 'DEV APT terminal-log control passed; no native appliance claim\n'

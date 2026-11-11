#!/usr/bin/env bash
set -euo pipefail
(( $# == 1 )) || { echo 'Usage: static-package.sh PACKAGE' >&2; exit 2; }
package=$(realpath -- "$1")
[[ $(dpkg-deb -f "$package" Package) = andeiva-firewall-preview ]]
[[ $(dpkg-deb -f "$package" Architecture) = amd64 ]]
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
dpkg-deb -x "$package" "$stage/root"
dpkg-deb -e "$package" "$stage/control"
for binary in usr/bin/andeiva usr/lib/andeiva-preview/andeiva-preview; do
  [[ -x "$stage/root/$binary" ]]
done
version=$(dpkg-deb -f "$package" Version)
expected=$(printf '{"product":"ANDEIVA Security Gateway","version":"%s","channel":"experimental","update_status":"unavailable"}' "$version")
[[ $("$stage/root/usr/bin/andeiva" --version) = "$expected" ]]
for script in preinst postinst prerm postrm; do sh -n "$stage/control/$script"; done
[[ -s "$stage/root/usr/share/andeiva-preview/web/index.html" ]]
[[ -s "$stage/root/usr/share/doc/andeiva-firewall-preview/dependencies/npm-inventory.json" ]]
[[ -s "$stage/root/usr/share/doc/andeiva-firewall-preview/dependencies/LICENSE.react" ]]
dependencies="$stage/root/usr/share/doc/andeiva-firewall-preview/dependencies"
for file in go.mod go.sum go-inventory.jsonl golang-x-LICENSE.txt golang-x-PATENTS.txt SHA256SUMS; do
  [[ -s "$dependencies/$file" ]]
done
(cd "$dependencies" && sha256sum --check --strict SHA256SUMS >/dev/null)
[[ $(sha256sum "$dependencies/golang-x-LICENSE.txt" | cut -d ' ' -f 1) = 911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad ]]
[[ $(sha256sum "$dependencies/golang-x-PATENTS.txt" | cut -d ' ' -f 1) = 96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc ]]
grep -q '"path":"golang.org/x/crypto","version":"v0.58.0"' "$dependencies/go-inventory.jsonl"
grep -q '"path":"golang.org/x/sys","version":"v0.49.0"' "$dependencies/go-inventory.jsonl"
grep -q '^golang.org/x/crypto v0.58.0 h1:' "$dependencies/go.sum"
grep -q '^golang.org/x/sys v0.49.0 h1:' "$dependencies/go.sum"
bash -n "$stage/root/usr/share/doc/andeiva-firewall-preview/tests/native.sh"
bash "$stage/root/usr/share/doc/andeiva-firewall-preview/tests/native.sh" --help >/dev/null
if bash "$stage/root/usr/share/doc/andeiva-firewall-preview/tests/native.sh" >/dev/null 2>&1; then
  echo ANDEIVA_PREVIEW_MISSING_TEST_CONSENT >&2; exit 1
else
  [[ $? == 2 ]]
fi
for language in en es pt; do
  [[ -s "$stage/root/usr/share/doc/andeiva-firewall-preview/firewalladmin/docs/$language.md" ]]
  grep -q '../firewalladmin/docs/' "$stage/root/usr/share/doc/andeiva-firewall-preview/docs/$language.md"
  console="$stage/root/usr/share/doc/andeiva-firewall-preview/console/$language.md"
  [[ -s "$console" && -s "$stage/root/usr/share/doc/andeiva-firewall-preview/docs/$language.md" ]]
  if ! grep -Fq "(../docs/$language.md#" "$console" || grep -Fq '../../packaging/preview/docs/' "$console"; then
    echo ANDEIVA_PREVIEW_CONSOLE_GUIDE_LINK >&2; exit 1
  fi
done
if find "$stage/root" -type f \( -name '*.key' -o -name 'accounts.json' -o -name 'identities.json' \) | read -r _; then
  echo ANDEIVA_PREVIEW_SECRET_IN_PACKAGE >&2; exit 1
fi
if find "$stage/root" -perm /6000 -type f | read -r _; then echo ANDEIVA_PREVIEW_SETID_FILE >&2; exit 1; fi
(cd "$stage/root" && md5sum -c "$stage/control/md5sums" >/dev/null)
units="$stage/root/usr/lib/systemd/system"
grep -q '^User=andeiva-preview-api$' "$units/andeiva-preview-api.service"
grep -q '^User=andeiva-preview-helper$' "$units/andeiva-preview-helper.service"
grep -q '^CapabilityBoundingSet=$' "$units/andeiva-preview-api.service"
grep -q '^AmbientCapabilities=$' "$units/andeiva-preview-api.service"
grep -q '^RestartMode=direct$' "$units/andeiva-preview-api.service"
grep -q '^RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK$' "$units/andeiva-preview-api.service"
grep -q '^CapabilityBoundingSet=CAP_NET_ADMIN$' "$units/andeiva-preview-helper.service"
grep -q '^NetworkNamespacePath=/run/andeiva-preview/netns/gateway$' "$units/andeiva-preview-helper.service"
! grep -q '^User=' "$units/andeiva-preview-namespaces.service"
grep -q '^CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_CHOWN CAP_DAC_OVERRIDE CAP_KILL$' "$units/andeiva-preview-namespaces.service"
grep -q '^NoNewPrivileges=yes$' "$units/andeiva-preview-namespaces.service"
grep -q '^BindToDevice=lo$' "$units/andeiva-preview-api.socket"
! grep -q '^WantedBy=sockets.target$' "$units/andeiva-preview-api.socket"
! grep -E '^(ExecStart|ExecStop).*\b(nft|iptables)\b' "$units"/*
printf 'PASS: package contents, checksums, scripts and privilege boundaries; no privileged runtime executed\n'

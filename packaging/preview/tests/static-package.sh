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
for script in preinst postinst prerm postrm; do sh -n "$stage/control/$script"; done
[[ -s "$stage/root/usr/share/andeiva-preview/web/index.html" ]]
[[ -s "$stage/root/usr/share/doc/andeiva-firewall-preview/dependencies/npm-inventory.json" ]]
[[ -s "$stage/root/usr/share/doc/andeiva-firewall-preview/dependencies/LICENSE.react" ]]
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
grep -q '^CapabilityBoundingSet=CAP_NET_ADMIN$' "$units/andeiva-preview-helper.service"
grep -q '^NetworkNamespacePath=/run/andeiva-preview/netns/gateway$' "$units/andeiva-preview-helper.service"
! grep -q '^User=' "$units/andeiva-preview-namespaces.service"
grep -q '^CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_CHOWN CAP_DAC_OVERRIDE CAP_KILL$' "$units/andeiva-preview-namespaces.service"
grep -q '^NoNewPrivileges=yes$' "$units/andeiva-preview-namespaces.service"
grep -q '^BindToDevice=lo$' "$units/andeiva-preview-api.socket"
! grep -q '^WantedBy=sockets.target$' "$units/andeiva-preview-api.socket"
! grep -E '^(ExecStart|ExecStop).*\b(nft|iptables)\b' "$units"/*
printf 'PASS: package contents, checksums, scripts and privilege boundaries; no privileged runtime executed\n'

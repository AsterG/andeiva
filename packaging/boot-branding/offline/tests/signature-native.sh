#!/usr/bin/env bash
# DEV only: private fixture keys are temporary and never packaged.
set -euo pipefail
umask 077
(( EUID != 0 && $# == 1 )) || exit 1
[[ -f "$1" && ! -L "$1" ]] || exit 1
for tool in gpg sqv go mktemp; do command -v "$tool" >/dev/null || exit 1; done
signed_release=$(realpath -e "$1")
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scratch=$(mktemp -d /tmp/andeiva-signature-fixture.XXXXXXXX)
cleanup() {
  case "$scratch" in /tmp/andeiva-signature-fixture.*) rm -rf -- "$scratch" ;; *) exit 1 ;; esac
}
trap cleanup EXIT
mkdir -m 0700 "$scratch/key"
gpg --homedir "$scratch/key" --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'ANDEIVA negative signature fixture' ed25519 sign 1d > "$scratch/keygen.log" 2>&1
printf 'Codename: trixie\nForeign signer test only.\n' > "$scratch/message"
gpg --homedir "$scratch/key" --batch --yes --pinentry-mode loopback --passphrase '' --armor --output "$scratch/foreign.asc" --clear-sign "$scratch/message" > "$scratch/sign.log" 2>&1
gpg --homedir "$scratch/key" --batch --verify "$scratch/foreign.asc" > "$scratch/own-verify.log" 2>&1
export ANDEIVA_TEST_DEBIAN_RELEASE="$signed_release" ANDEIVA_TEST_FOREIGN_RELEASE="$scratch/foreign.asc"
cd "$source_dir"
go test -count=1 -run '^TestNativeSQVTrustedAlteredAndForeignSignature$' -v ./check

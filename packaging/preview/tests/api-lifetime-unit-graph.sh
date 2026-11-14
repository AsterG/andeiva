#!/usr/bin/env bash
set -euo pipefail
(( $# <= 1 )) || exit 2
units=${1:-$(cd -- "$(dirname -- "$0")/.." && pwd)}
value() { sed -n "s/^$2=//p" "$units/$1"; }
[[ $(value andeiva-preview.target Requires) = 'andeiva-preview-namespaces.service andeiva-preview-helper.service' ]]
[[ $(value andeiva-preview.target Wants) = 'andeiva-preview-api.socket andeiva-preview-api.service' ]]
[[ $(value andeiva-preview.target After) = 'andeiva-preview-namespaces.service andeiva-preview-helper.service andeiva-preview-api.socket andeiva-preview-api.service' ]]
for unit in andeiva-preview-api.service andeiva-preview-api.socket; do
  [[ $(value "$unit" PartOf) = andeiva-preview.target ]]
  ! grep -Eq '^(BindsTo|OnFailure|ExecStop|ExecStopPost|PropagatesStopTo)=' "$units/$unit"
done
# API depends on the helper/socket, never the reverse. Explicit target stop and
# helper/namespace failure still tear down the isolated appliance coherently.
[[ $(value andeiva-preview-api.service Requires) = 'andeiva-preview-helper.service andeiva-preview-api.socket' ]]
[[ $(value andeiva-preview-api.socket Service) = andeiva-preview-api.service ]]
for unit in andeiva-preview-helper.service andeiva-preview-namespaces.service; do
  [[ $(value "$unit" PartOf) = andeiva-preview.target ]]
  grep -Eq '^ExecStopPost=.*systemctl --no-block stop andeiva-preview.target$' "$units/$unit"
  ! grep -Eq '^(Requires|BindsTo|After)=.*andeiva-preview-api' "$units/$unit"
done
printf 'PASS: administration stop/failure does not propagate to helper or namespaces; explicit target shutdown remains intact\n'

# Root alone publishes bounded recovery anchors; retention survives a failed
# service, but acceptance and removal still require actual manager readback.
[[ $(value andeiva-preview-grouped.service NotifyAccess) = main ]]
[[ $(value andeiva-preview-grouped.service FileDescriptorStoreMax) = 7 ]]
[[ $(value andeiva-preview-grouped.service FileDescriptorStorePreserve) = yes ]]
[[ $(value andeiva-preview-grouped.service ReadWritePaths) = $'/var/lib/andeiva-preview/grouped /var/lib/andeiva-preview/audit /run/andeiva-preview/grouped\n/var/lib/andeiva-preview-package/grouped-retirement-v3 /var/lib/andeiva-preview-package/grouped-scope-v3' ]]
printf 'PASS: grouped Root FD store is bounded and main-only; writes use exact preallocated slots\n'

[[ $(value andeiva-preview-grouped.service Delegate) = no ]]

[[ $(value andeiva-preview-grouped.service PrivateMounts) = yes ]]

# Root alone may enter/restore an authenticated retained mount namespace.
[[ $(value andeiva-preview-grouped.service NoNewPrivileges) = yes ]]
[[ $(value andeiva-preview-grouped.service CapabilityBoundingSet) = 'CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_DAC_READ_SEARCH CAP_KILL CAP_CHOWN' ]]
[[ $(value andeiva-preview-api.service CapabilityBoundingSet) = '' ]]
[[ $(value andeiva-preview-helper.service CapabilityBoundingSet) = CAP_NET_ADMIN ]]
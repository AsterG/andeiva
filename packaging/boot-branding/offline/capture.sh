#!/bin/bash
# Invoked only through the outer timeout; both producer and logger share its group.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C TZ=UTC
unset APT_CONFIG BASH_ENV ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH
(( EUID == 0 && $# == 2 )) || exit 1
operation=$1
leaf=$2
bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ "$bundle" =~ ^/var/lib/andeiva-boot-bundles/[0-9a-f]{64}$ ]]
id=${bundle##*/}
[[ "$operation" = simulate || "$operation" = install ]]
[[ "$leaf" = "$id" || ( "$operation" = simulate && "$leaf" =~ ^\.inspect\.[A-Za-z0-9]{8}$ ) ]]
stage="/var/backups/andeiva-boot-offline/$leaf"
[[ -d "$stage" && ! -L "$stage" && $(stat -c %u "$stage") = 0 && $(stat -c %a "$stage") = 700 ]]
[[ -f "$stage/apt.conf" && ! -L "$stage/apt.conf" && $(stat -c %u "$stage/apt.conf") = 0 && $(stat -c %a "$stage/apt.conf") = 600 ]]
cmp "$bundle/manifest.tsv" "$stage/manifest.tsv"
export APT_CONFIG="$stage/apt.conf"
if [[ "$operation" = simulate ]]; then
  log="$stage/simulation.log"
  packages=()
  cache_plan=$("$bundle/bin/check" cache-plan "$bundle")
  while IFS=$'\t' read -r _file cache_leaf hash; do
    staged="$stage/archives/$cache_leaf"
    [[ $(sha256sum "$staged" | cut -d ' ' -f1) = "$hash" ]]
    packages+=("$staged")
  done <<< "$cache_plan"
else
  log="$stage/install.log"
fi
[[ -f "$log" && ! -L "$log" && $(stat -c %u "$log") = 0 && $(stat -c %a "$log") = 600 && ! -s "$log" ]]
# Save PIPESTATUS immediately; either producer or logger failure is a failure.
set +e
if [[ "$operation" = simulate ]]; then
  apt-get -s --no-download --no-install-recommends --no-remove --no-upgrade install "${packages[@]}" 2>&1 | "$bundle/bin/check" bounded-log "$bundle" >> "$log"
  statuses=("${PIPESTATUS[@]}")
else
  unshare --mount --propagation private /bin/bash "$bundle/install-in-namespace.sh" "$id" 2>&1 | "$bundle/bin/check" bounded-log "$bundle" >> "$log"
  statuses=("${PIPESTATUS[@]}")
fi
set -e
(( ${#statuses[@]} == 2 && statuses[0] == 0 && statuses[1] == 0 )) || exit 1

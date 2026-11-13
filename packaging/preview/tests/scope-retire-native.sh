#!/usr/bin/env bash
set -euo pipefail

# Root executes this only on an authorized disposable Debian client. The test
# binary, not this driver, is MainPID and sends authenticated FD-store messages.
if [[ $# != 2 || $1 != --isolated-lab || ${EUID} != 0 || -n ${CI:-} ]]; then
  printf '%s\n' 'Requires --isolated-lab TEST_BINARY, root, and no CI.' >&2
  exit 2
fi
grep -qx 'ID=debian' /etc/os-release
grep -qx 'VERSION_ID="13"' /etc/os-release
[[ ! -L $2 && -f $2 && -x $2 ]]
binary=$(realpath -e -- "$2")
[[ $(stat -c '%u:%h' -- "$binary") == 0:1 ]]
mode=$(stat -c '%a' -- "$binary")
(( (8#$mode & 0022) == 0 ))
[[ $(stat -c '%u:%a' -- "$(dirname -- "$binary")") == 0:755 ]]
unit=andeiva-preview-grouped.service
for name in "$unit" andeiva-preview-grouped.socket; do
  [[ $(timeout 4s systemctl show -p LoadState --value "$name") == not-found ]]
done
for socket in /run/systemd/private /run/systemd/notify /run/dbus/system_bus_socket; do
  [[ -S $socket && ! -L $socket ]]
done
fixture=$(mktemp -d /var/backups/andeiva-scope-retire.XXXXXXXX)
chmod 0755 "$fixture"
root=$fixture/root
mkdir -m 0755 "$root"
[[ ! -L $root && $(realpath -e -- "$root") == "$root" ]]
[[ $(stat -c '%u:%g:%a' -- "$root") == 0:0:755 ]]
for directory in etc usr proc sys dev run run/systemd run/dbus var var/lib var/lib/andeiva-preview var/lib/andeiva-preview/grouped run/andeiva-preview run/andeiva-preview/grouped fixture; do
  mkdir -m 0755 "$root/$directory"
done
mkdir -m 0700 "$root/var/lib/andeiva-preview-package"
mkdir -m 0755 "$root/etc/andeiva-preview"
# MountAPIVFS supplies /run only as a fallback. Explicitly bind the complete
# private /run at that same destination, so the fallback cannot hide a child
# bind's source beneath $root/run. Never bind or create the host's /run tree.
for directory in run run/andeiva-preview run/andeiva-preview/grouped var/lib/andeiva-preview var/lib/andeiva-preview/grouped; do
  path=$root/$directory
  [[ -d $path && ! -L $path && $(realpath -e -- "$path") == "$path" ]]
  [[ $(stat -c '%u:%g:%a' -- "$path") == 0:0:755 ]]
done
[[ $(stat -c '%u:%g:%a' -- "$root/var/lib/andeiva-preview-package") == 0:0:700 ]]
ln -s usr/bin "$root/bin"
ln -s usr/sbin "$root/sbin"
ln -s usr/lib "$root/lib"
ln -s usr/lib64 "$root/lib64"
printf '%s\n' 'root:x:0:0:root:/root:/bin/false' 'scope-api:x:62001:62001:fixture:/nonexistent:/bin/false' 'scope-helper:x:62002:62003:fixture:/nonexistent:/bin/false' > "$root/etc/passwd"
printf '%s\n' 'root:x:0:' 'scope-api:x:62001:' 'scope-ipc:x:62003:' 'scope-reader:x:62004:' > "$root/etc/group"
printf '%s\n' 'passwd: files' 'group: files' 'hosts: files' > "$root/etc/nsswitch.conf"
printf '%s\n' '127.0.0.1 localhost' > "$root/etc/hosts"
chmod 0644 "$root/etc/passwd" "$root/etc/group" "$root/etc/nsswitch.conf" "$root/etc/hosts"
install -o root -g root -m 0555 -- "$binary" "$root/fixture/native.test"
sha256sum -- "$binary" "$root/fixture/native.test" > "$fixture/artifacts.sha256"
printf '%s\n' "$fixture"
# These are fixture capabilities, including mount-namespace creation. They are
# not a proposed appliance/helper capability budget. No host NIC is configured.
timeout 8s systemd-run --unit="$unit" --service-type=exec \
  --property="RootDirectory=$root" --property=MountAPIVFS=yes \
  --property="BindPaths=$root/run:/run:norbind" \
  --property='BindReadOnlyPaths=/usr /sys /etc/os-release:/etc/os-release /run/systemd/system /run/systemd/private /run/systemd/notify /run/dbus/system_bus_socket' \
  --property=PrivateMounts=yes --property=PrivateDevices=yes \
  --property=Delegate=no --property=NotifyAccess=main \
  --property=FileDescriptorStoreMax=7 --property=FileDescriptorStorePreserve=yes \
  --property=KillMode=control-group --property=Restart=on-failure --property=RemainAfterExit=yes \
  --property=RestartSec=1s --property=StartLimitIntervalSec=240s --property=StartLimitBurst=2 \
  --property=RuntimeMaxSec=100s --property=TimeoutStopSec=5s \
  --property=LimitNOFILE=256 --property=MemoryMax=384M --property=TasksMax=128 \
  --property=CPUAccounting=yes --property=MemoryAccounting=yes --property=UMask=0077 \
  --property='CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_KILL' \
  --setenv=ANDEIVA_SCOPE_RETIRE_NATIVE=1 \
  /fixture/native.test -test.run '^TestRoutedScopeRetireV3Native$' -test.count=1 -test.timeout=90s -test.v

deadline=$((SECONDS + 210))
while (( SECONDS < deadline )); do
  state=$(timeout 4s systemctl show -p ActiveState --value "$unit")
  substate=$(timeout 4s systemctl show -p SubState --value "$unit")
  if [[ $state == active && $substate == exited ]]; then break; fi
  if [[ $state == inactive || $state == failed ]]; then break; fi
  sleep 1
done
timeout 5s journalctl --no-pager -u "$unit" > "$fixture/journal-all.txt"
timeout 5s systemctl show "$unit" > "$fixture/unit.txt"
if [[ ${state:-} != active || ${substate:-} != exited || ! -f $root/fixture/retired.json ]]; then
  printf '%s\n' 'Qualification did not pass. Evidence and manager-held descriptors retained; no automatic stop or deletion.' >&2
  exit 1
fi
[[ $(timeout 4s systemctl show -p NFileDescriptorStore --value "$unit") == 0 ]]
[[ $(timeout 4s systemctl show -p MainPID --value "$unit") == 0 ]]
[[ $(timeout 4s systemctl show -p NRestarts --value "$unit") == 1 ]]
invocation=$(timeout 4s systemctl show -p InvocationID --value "$unit")
[[ $invocation =~ ^[a-f0-9]{32}$ && $(cat "$root/fixture/recovery-attempt-$invocation") == "$invocation" ]]
[[ $(timeout 4s systemctl show -p RootDirectory --value "$unit") == "$root" ]]
[[ $(timeout 4s systemctl show -p Result --value "$unit") == success ]]
[[ $(timeout 4s systemctl show -p ExecMainCode --value "$unit") == 1 ]]
[[ $(timeout 4s systemctl show -p ExecMainStatus --value "$unit") == 0 ]]
timeout 5s journalctl --no-pager -o cat "_SYSTEMD_INVOCATION_ID=$invocation" "_SYSTEMD_UNIT=$unit" > "$fixture/journal.txt"
grep -qx PASS "$fixture/journal.txt"
# Only this successfully completed, correlated invocation may be stopped. On
# any earlier error the driver deliberately leaves the unit/store for review.
timeout 8s systemctl stop "$unit"
printf '%s\n' 'ANDEIVA_SCOPE_RETIRE_NATIVE_PASS (component; no management socket activation or host policy changes)'
# Retain all source data/results, including the exact receipt, for Root review.

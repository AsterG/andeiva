#!/usr/bin/env bash
# Opt-in storage tests on a finite filesystem in a private mount namespace.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

die() { printf 'ANDEIVA_STORAGE_LAB: %s\n' "$1" >&2; exit 1; }
[[ $EUID = 0 && $# = 4 ]] || die 'root and explicit laboratory authorization required'
task_mode=$1
task_binary=$(realpath -e -- "$2")
task_sha=$3
task_namespace=$4
[[ $task_sha =~ ^[a-f0-9]{64}$ && -f $task_binary && ! -L $2 ]] || die 'invalid test executable'
[[ $(stat -c '%u' "$task_binary") = 0 ]] || die 'test executable must be owned by root'
task_permissions=$(stat -c '%a' "$task_binary")
(( (8#$task_permissions & 022) == 0 )) || die 'test executable is writable by other users'
[[ $(sha256sum "$task_binary" | cut -d ' ' -f1) = "$task_sha" ]] || die 'test executable checksum mismatch'
[[ $(uname -m) = x86_64 ]] || die 'Debian 13 AMD64 required'
# os-release is supplied by the authorized laboratory operating system.
. /etc/os-release
[[ $ID = debian && $VERSION_ID = 13 ]] || die 'Debian 13 required'
for task_command in unshare mount umount mountpoint runuser getent timeout; do
  command -v "$task_command" >/dev/null || die 'required laboratory tool is absent'
done
[[ $(id -u andeiva) = 1000 && $(id -g andeiva) = 1000 ]] || die 'laboratory account must be andeiva, UID/GID 1000'
task_script=$(realpath -e -- "$0")
[[ $(stat -c '%u' "$task_script") = 0 ]] || die 'harness must be owned by root'
task_permissions=$(stat -c '%a' "$task_script")
(( (8#$task_permissions & 022) == 0 )) || die 'harness is writable by other users'
# Reopening a root-owned file is unsafe if another user can replace an ancestor.
trusted_ancestors() {
  local task_parent
  task_parent=$(dirname -- "$1")
  while :; do
    [[ $(stat -c '%u' "$task_parent") = 0 ]] || die 'input directory must be owned by root'
    task_permissions=$(stat -c '%a' "$task_parent")
    (( (8#$task_permissions & 022) == 0 )) || die 'input directory is writable by other users'
    [[ $task_parent = / ]] && break
    task_parent=$(dirname -- "$task_parent")
  done
}
trusted_ancestors "$task_script"
trusted_ancestors "$task_binary"

if [[ $task_mode = --authorized-debian-lab ]]; then
  [[ $task_namespace = --isolated-storage-only ]] || die 'explicit isolated-storage authorization required'
  task_parent_namespace=$(readlink /proc/self/ns/mnt)
  task_parent_network=$(readlink /proc/self/ns/net)
  exec 9</proc/self/ns/mnt
  exec 10</proc/self/ns/net
  export ANDEIVA_STORAGE_PARENT_NETWORK="$task_parent_network"
  exec unshare --mount --net --propagation private -- /bin/bash "$task_script" --inside "$task_binary" "$task_sha" "$task_parent_namespace"
fi
[[ $task_mode = --inside && $task_namespace =~ ^mnt:\[[0-9]+\]$ ]] || die 'invalid execution mode'
[[ $(readlink /proc/self/fd/9) = "$task_namespace" && $(readlink /proc/self/ns/mnt) != "$task_namespace" ]] || die 'private mount namespace required'
[[ $(readlink /proc/self/fd/10) = "${ANDEIVA_STORAGE_PARENT_NETWORK:-}" && $(readlink /proc/self/ns/net) != "${ANDEIVA_STORAGE_PARENT_NETWORK:-}" ]] || die 'private network namespace required'
exec 9<&-
exec 10<&-

task_base=$(mktemp -d /tmp/andeiva-storage-pressure.XXXXXXXX)
[[ $task_base =~ ^/tmp/andeiva-storage-pressure\.[A-Za-z0-9]{8}$ ]] || die 'invalid temporary directory'
chmod 0755 "$task_base"
task_volume=$task_base/volume
cleanup() {
  task_result=$?
  trap - EXIT
  if mountpoint -q "$task_volume"; then
    umount -- "$task_volume" || { printf 'ANDEIVA_STORAGE_LAB: unmount failed\n' >&2; exit 1; }
  fi
  # The test contents existed only in the unmounted tmpfs. No recursive deletion.
  if [[ -d $task_volume ]]; then rmdir -- "$task_volume" || exit 1; fi
  if [[ -e $task_base/runner.test ]]; then rm -- "$task_base/runner.test" || exit 1; fi
  rmdir -- "$task_base" || exit 1
  exit "$task_result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 0700 "$task_volume"
install -o root -g root -m 0555 "$task_binary" "$task_base/runner.test"
[[ $(sha256sum "$task_base/runner.test" | cut -d ' ' -f1) = "$task_sha" ]] || die 'copied executable checksum mismatch'
for task_case in bytes inodes readonly; do
  mount -t tmpfs -o size=16M,nr_inodes=256,mode=0700,uid=1000,gid=1000,nosuid,nodev,noexec tmpfs "$task_volume"
  install -d -o andeiva -g andeiva -m 0700 "$task_volume/store"
  if [[ $task_case = readonly ]]; then
    mount -o remount,ro "$task_volume"
  fi
  printf 'ANDEIVA_STORAGE_LAB_CASE=%s\n' "$task_case"
  timeout --kill-after=5 120 runuser -u andeiva -- env -i PATH=/usr/bin:/bin HOME=/nonexistent TMPDIR="$task_volume" \
    ANDEIVA_STORAGE_PRESSURE=1 ANDEIVA_STORAGE_PRESSURE_MODE="$task_case" ANDEIVA_STORAGE_PRESSURE_ROOT="$task_volume" \
    "$task_base/runner.test" -test.run '^TestRealStoragePressure$' -test.v -test.timeout 90s
  umount -- "$task_volume"
done
printf 'ANDEIVA_STORAGE_LAB_RESULT=pass\n'

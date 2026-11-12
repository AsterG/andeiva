#!/usr/bin/env bash
# Opt-in storage tests on a finite filesystem in a private mount namespace.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

capture_test_output() {
  local task_log=$1
  shift
  # Bound the log writer only; pressure writes must reach the filesystem limit.
  "$@" 2>&1 | (ulimit -f 1024; tee "$task_log")
}

die() { printf 'ANDEIVA_STORAGE_LAB: %s\n' "$1" >&2; exit 1; }
verify_test_log() {
  local task_log=$1 task_test=$2 task_case=${3:-}
  [[ $task_test = TestNativeVolumePressure || $task_test = TestRealStoragePressure ]] || return 1
  grep -Fqx -- "=== RUN   $task_test" "$task_log" || return 1
  grep -Eq -- "^--- PASS: $task_test \(([0-9]+h)?([0-9]+m)?[0-9]+([.][0-9]+)?s\)$" "$task_log" || return 1
  if [[ $task_test = TestNativeVolumePressure ]]; then
    [[ $task_case = bytes || $task_case = inodes || $task_case = readonly || $task_case = open-deleted ]] || return 1
    grep -Fqx -- "ANDEIVA_NATIVE_VOLUME_CASE_PASS=$task_case" "$task_log" || return 1
  fi
}
if [[ $EUID = 0 && $# = 7 && $1 = --authorized-debian-volumes ]]; then
  export ANDEIVA_STORAGE_VOLUME_ID=$7
  [[ $ANDEIVA_STORAGE_VOLUME_ID =~ ^[a-f0-9]{32}$ ]] || die 'invalid preparation ID'
  export ANDEIVA_STORAGE_INSPECTOR=$5 ANDEIVA_STORAGE_INSPECTOR_SHA=$6
  set -- --authorized-debian-lab "$2" "$3" "$4"
fi
[[ $EUID = 0 && $# = 4 ]] || die 'root and explicit laboratory authorization required'
task_mode=$1
task_binary=$(realpath -e -- "$2")
task_sha=$3
task_namespace=$4
[[ $task_sha =~ ^[a-f0-9]{64}$ && -f $task_binary && ! -L $2 ]] || die 'invalid test executable'
(( $(stat -c '%s' "$task_binary") > 0 && $(stat -c '%s' "$task_binary") <= 32*1024*1024 )) || die 'test executable exceeds size limit'
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
(( $(stat -c '%s' "$task_script") <= 128*1024 )) || die 'harness exceeds size limit'
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

task_volume_id=${ANDEIVA_STORAGE_VOLUME_ID:-}
if [[ -n $task_volume_id ]]; then
  [[ $task_volume_id =~ ^[a-f0-9]{32}$ && ${ANDEIVA_STORAGE_INSPECTOR_SHA:-} =~ ^[a-f0-9]{64}$ ]] || die 'invalid volume arguments'
  [[ ${ANDEIVA_STORAGE_INSPECTOR:-} = /* && ! -L $ANDEIVA_STORAGE_INSPECTOR ]] || die 'invalid inspector'
  task_inspector=$(realpath -e -- "$ANDEIVA_STORAGE_INSPECTOR")
  [[ -f $task_inspector && $(stat -c '%u:%h' "$task_inspector") = 0:1 ]] || die 'invalid inspector ownership'
  (( $(stat -c '%s' "$task_inspector") > 0 && $(stat -c '%s' "$task_inspector") <= 32*1024*1024 )) || die 'inspector exceeds size limit'
  task_permissions=$(stat -c '%a' "$task_inspector")
  (( (8#$task_permissions & 022) == 0 )) || die 'inspector writable by others'
  trusted_ancestors "$task_inspector"
  [[ $(sha256sum "$task_inspector" | cut -d ' ' -f1) = "$ANDEIVA_STORAGE_INSPECTOR_SHA" ]] || die 'inspector checksum mismatch'
fi

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

if [[ -n $task_volume_id ]]; then
  # Only copied images are mounted. Originals remain byte-for-byte inspectable.
  task_original=/var/lib/andeiva-storage-lab/volumes-$task_volume_id
  task_plan=$("$task_inspector" --authorized-debian-lab --operation harness-plan --id "$task_volume_id") || die 'original preparation verification failed'
  mapfile -t task_rows <<< "$task_plan"
  [[ ${#task_rows[@]} = 5 ]] || die 'invalid typed plan length'
  IFS=$'\t' read -r task_plan_tag task_plan_id task_plan_hash task_plan_extra <<< "${task_rows[0]}"
  [[ $task_plan_tag = ANDEIVA_STORAGE_PLAN_V1 && $task_plan_id = "$task_volume_id" && $task_plan_hash =~ ^[a-f0-9]{64}$ && -z $task_plan_extra ]] || die 'invalid typed plan'
  for task_tool in /usr/sbin/losetup /usr/bin/mount /usr/bin/umount /usr/bin/cp /usr/bin/sync /usr/bin/timeout; do
    [[ -f $task_tool && -x $task_tool && $(stat -c '%u' "$task_tool") = 0 ]] || die 'fixed laboratory tool absent'
    task_permissions=$(stat -c '%a' "$task_tool")
    (( (8#$task_permissions & 022) == 0 )) || die 'fixed laboratory tool writable by others'
    trusted_ancestors "$task_tool"
  done
  task_pressure_base=/var/lib/andeiva-storage-pressure
  if [[ ! -e $task_pressure_base ]]; then mkdir -m 0700 -- "$task_pressure_base"; fi
  [[ ! -L $task_pressure_base && $(stat -c '%u:%g:%a' "$task_pressure_base") = 0:0:700 ]] || die 'unsafe pressure base'
  trusted_ancestors "$task_pressure_base/entry"
  [[ -z $(find "$task_pressure_base" -mindepth 1 -maxdepth 1 -print -quit) ]] || die 'previous pressure workspace requires authorized recovery'
  task_available=$(df -B1 --output=avail "$task_pressure_base" | tail -n 1 | tr -d ' ')
  [[ $task_available =~ ^[0-9]+$ ]] && (( task_available >= 512*1024*1024 )) || die 'insufficient reserved-copy headroom'
  task_free_inodes=$(stat -f -c '%d' "$task_pressure_base")
  [[ $task_free_inodes =~ ^[0-9]+$ ]] && (( task_free_inodes >= 32 )) || die 'insufficient copy inodes'
  task_base=$(mktemp -d "$task_pressure_base/test.XXXXXXXX")
  [[ $task_base =~ ^/var/lib/andeiva-storage-pressure/test\.[A-Za-z0-9]{8}$ ]] || die 'invalid pressure workspace'
  declare -a task_loops=() task_mounts=() task_images=() task_logs=()
  cleanup_volumes() {
    task_result=$?; trap - EXIT
    local task_index task_loop task_mount task_backing
    for ((task_index=${#task_mounts[@]}-1; task_index>=0; task_index--)); do
      task_mount=${task_mounts[task_index]}
      if mountpoint -q "$task_mount"; then /usr/bin/umount -- "$task_mount" || { printf 'ANDEIVA_STORAGE_LAB: mount retained for recovery\n' >&2; exit 1; }; fi
    done
    for task_loop in "${task_loops[@]}"; do
      if /usr/sbin/losetup "$task_loop" >/dev/null 2>&1; then
        task_backing=$(/usr/sbin/losetup --noheadings --output BACK-FILE "$task_loop")
        [[ $task_backing = "$task_base/"*.img ]] || { printf 'ANDEIVA_STORAGE_LAB: loop identity changed\n' >&2; exit 1; }
        /usr/sbin/losetup --detach "$task_loop" || exit 1
      fi
    done
    for task_image in "${task_images[@]}"; do
      [[ -z $(/usr/sbin/losetup --associated "$task_image") ]] || { printf 'ANDEIVA_STORAGE_LAB: loop still associated\n' >&2; exit 1; }
    done
    # Failed tests keep evidence and the owned workspace after safe detachment.
    if [[ $task_result != 0 ]]; then
      printf 'ANDEIVA_STORAGE_LAB: failed workspace retained: %s\n' "$task_base" >&2
      exit "$task_result"
    fi
    for task_mount in "${task_mounts[@]}"; do rmdir -- "$task_mount" || exit 1; done
    # Deletion requires every owned image to be detached. Never force/lazy unmount.
    for task_image in "${task_images[@]}"; do
      [[ -z $(/usr/sbin/losetup --associated "$task_image") ]] || exit 1
      [[ -f $task_image && ! -L $task_image && $(stat -c '%u:%g:%a:%h' "$task_image") = 0:0:600:1 ]] || exit 1
      rm -- "$task_image" || exit 1
    done
    for task_log in "${task_logs[@]}"; do rm -- "$task_log" || exit 1; done
    [[ ! -e $task_base/runner.test ]] || rm -- "$task_base/runner.test"
    rmdir -- "$task_base" || exit 1
    if [[ $task_result = 0 ]]; then printf 'ANDEIVA_STORAGE_VOLUME_RESULT=pass\n'; fi
    exit "$task_result"
  }
  trap cleanup_volumes EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  install -o root -g root -m 0555 "$task_binary" "$task_base/runner.test"
  [[ $(sha256sum "$task_base/runner.test" | cut -d ' ' -f1) = "$task_sha" ]] || die 'copied runner checksum mismatch'
  task_domains=(config audit observations recovery)
  task_sizes=(134217728 134217728 67108864 67108864)
  task_inodes=(8192 4096 1024 2048)
  for task_index in 0 1 2 3; do
    IFS=$'\t' read -r task_domain task_source task_hash task_uuid task_size task_inode task_extra <<< "${task_rows[task_index+1]}"
    [[ $task_domain = "${task_domains[task_index]}" && $task_source = "$task_original/$task_domain.img" && $task_hash =~ ^[a-f0-9]{64}$ && $task_uuid =~ ^[a-f0-9]{32}$ && $task_size = "${task_sizes[task_index]}" && $task_inode = "${task_inodes[task_index]}" && -z $task_extra ]] || die 'typed plan mismatch'
    [[ -f $task_source && ! -L $task_source && $(stat -c '%u:%g:%a:%h:%s' "$task_source") = "0:0:600:1:$task_size" ]] || die 'unsafe original image'
    task_identity=$(stat -c '%d:%i' "$task_source")
    [[ -z $(/usr/sbin/losetup --associated "$task_source") ]] || die 'original image is attached'
    task_image=$task_base/$task_domain.img
    [[ ! -e $task_image ]] || die 'copy destination exists'
    /usr/bin/cp --reflink=never --sparse=never -- "$task_source" "$task_image"
    task_images+=("$task_image")
    chmod 0600 "$task_image"
    [[ $(stat -c '%d:%i' "$task_source") = "$task_identity" && $(sha256sum "$task_source" | cut -d ' ' -f1) = "$task_hash" && $(sha256sum "$task_image" | cut -d ' ' -f1) = "$task_hash" ]] || die 'copy identity/hash mismatch'
    (( $(stat -c '%b' "$task_image") * 512 >= task_size )) || die 'copy is sparse'
    /usr/bin/sync -f "$task_image"
    task_loop=$(/usr/sbin/losetup --find --show --nooverlap "$task_image")
    [[ $task_loop =~ ^/dev/loop[0-9]+$ ]] || die 'invalid loop device'
    task_loops+=("$task_loop")
    task_mount=$task_base/$task_domain
    mkdir -m 0700 -- "$task_mount"
    task_mounts+=("$task_mount")
    /usr/bin/mount -t ext4 -o nosuid,nodev,noexec -- "$task_loop" "$task_mount"
    chmod 0700 "$task_mount"
  done
  for task_case in bytes inodes readonly open-deleted; do
    printf 'ANDEIVA_STORAGE_VOLUME_CASE=%s\n' "$task_case"
    task_log=$task_base/$task_case.log
    [[ ! -e $task_log ]] || die 'test log exists'
    : > "$task_log"; chmod 0600 "$task_log"; task_logs+=("$task_log")
    if [[ $task_case = readonly ]]; then /usr/bin/mount -o remount,ro -- "$task_base/observations"; fi
    capture_test_output "$task_log" /usr/bin/timeout --kill-after=5 180 env -i PATH=/usr/bin:/bin HOME=/nonexistent \
      ANDEIVA_STORAGE_NATIVE_VOLUMES=1 ANDEIVA_STORAGE_VOLUME_CASE="$task_case" ANDEIVA_STORAGE_VOLUME_ROOT="$task_base" \
      ANDEIVA_STORAGE_NATIVE_PARENT_MNT="$task_namespace" ANDEIVA_STORAGE_NATIVE_PARENT_NET="$ANDEIVA_STORAGE_PARENT_NETWORK" \
      "$task_base/runner.test" -test.run '^TestNativeVolumePressure$' -test.v -test.timeout 150s
    verify_test_log "$task_log" TestNativeVolumePressure "$task_case" || die 'native test did not prove execution and completion'
    if [[ $task_case = readonly ]]; then /usr/bin/mount -o remount,rw -- "$task_base/observations"; fi
  done
  [[ $("$task_inspector" --authorized-debian-lab --operation harness-plan --id "$task_volume_id") = "$task_plan" ]] || die 'original preparation changed'
  exit 0
fi

task_base=$(mktemp -d /tmp/andeiva-storage-pressure.XXXXXXXX)
[[ $task_base =~ ^/tmp/andeiva-storage-pressure\.[A-Za-z0-9]{8}$ ]] || die 'invalid temporary directory'
chmod 0755 "$task_base"
task_volume=$task_base/volume
declare -a task_logs=()
cleanup() {
  task_result=$?
  trap - EXIT
  if mountpoint -q "$task_volume"; then
    umount -- "$task_volume" || { printf 'ANDEIVA_STORAGE_LAB: unmount failed\n' >&2; exit 1; }
  fi
  if [[ $task_result != 0 ]]; then
    printf 'ANDEIVA_STORAGE_LAB: failed workspace retained: %s\n' "$task_base" >&2
    exit "$task_result"
  fi
  # The test contents existed only in the unmounted tmpfs. No recursive deletion.
  if [[ -d $task_volume ]]; then rmdir -- "$task_volume" || exit 1; fi
  if [[ -e $task_base/runner.test ]]; then rm -- "$task_base/runner.test" || exit 1; fi
  for task_log in "${task_logs[@]}"; do rm -- "$task_log" || exit 1; done
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
  task_log=$task_base/$task_case.log
  [[ ! -e $task_log ]] || die 'test log exists'
  : > "$task_log"; chmod 0600 "$task_log"; task_logs+=("$task_log")
  capture_test_output "$task_log" timeout --kill-after=5 120 runuser -u andeiva -- env -i PATH=/usr/bin:/bin HOME=/nonexistent TMPDIR="$task_volume" \
    ANDEIVA_STORAGE_PRESSURE=1 ANDEIVA_STORAGE_PRESSURE_MODE="$task_case" ANDEIVA_STORAGE_PRESSURE_ROOT="$task_volume" \
    "$task_base/runner.test" -test.run '^TestRealStoragePressure$' -test.v -test.timeout 90s
  verify_test_log "$task_log" TestRealStoragePressure || die 'legacy test did not prove execution and completion'
  umount -- "$task_volume"
done
printf 'ANDEIVA_STORAGE_LAB_RESULT=pass\n'

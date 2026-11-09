#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'TEXT'
Usage:
  bash vm-lifecycle.sh run --install-deb EXP1 --install-sha256 SHA256 --upgrade-deb EXP2 --upgrade-sha256 SHA256 --evidence-dir NEW_DIR --snapshot-ref REF --lab-ack ANDEIVA-ISOLATED-LAB
  bash vm-lifecycle.sh prepare-reboot --install-deb EXP1 --install-sha256 SHA256 --evidence-dir NEW_DIR --snapshot-ref REF --lab-ack ANDEIVA-ISOLATED-LAB
  bash vm-lifecycle.sh verify-after-reboot --evidence-dir EXISTING_DIR --snapshot-ref REF --lab-ack ANDEIVA-ISOLATED-LAB
  bash vm-lifecycle.sh cleanup-reboot --evidence-dir EXISTING_DIR --snapshot-ref REF --lab-ack ANDEIVA-ISOLATED-LAB

Only a disposable Debian 13 amd64 VMware lab with a user-confirmed recovery snapshot.
Run static-package.sh on a host/CI machine first; provide hashes from that trusted build.
No reboot, network configuration, apt operation or snapshot operation is performed.
Failure stops the test-owned service and retains package/evidence for diagnosis.
TEXT
}
[[ $# -ge 1 ]] || { usage; exit 2; }
mode=$1; shift
case "$mode" in run|prepare-reboot|verify-after-reboot|cleanup-reboot) ;; *) usage; exit 2;; esac
install_deb= install_hash= upgrade_deb= upgrade_hash= evidence= snapshot= acknowledgment=
while [[ $# -gt 0 ]]; do
  [[ $# -ge 2 ]] || fail 'Missing option value'
  case "$1" in
    --install-deb) [[ -z $install_deb ]] || fail 'Repeated option'; install_deb=$2;;
    --install-sha256) [[ -z $install_hash ]] || fail 'Repeated option'; install_hash=$2;;
    --upgrade-deb) [[ -z $upgrade_deb ]] || fail 'Repeated option'; upgrade_deb=$2;;
    --upgrade-sha256) [[ -z $upgrade_hash ]] || fail 'Repeated option'; upgrade_hash=$2;;
    --evidence-dir) [[ -z $evidence ]] || fail 'Repeated option'; evidence=$2;;
    --snapshot-ref) [[ -z $snapshot ]] || fail 'Repeated option'; snapshot=$2;;
    --lab-ack) [[ -z $acknowledgment ]] || fail 'Repeated option'; acknowledgment=$2;;
    *) fail 'Unknown option';;
  esac
  shift 2
done
[[ $EUID == 0 ]] || fail 'Root is required inside the explicitly authorized VM only'
[[ $acknowledgment == ANDEIVA-ISOLATED-LAB ]] || fail 'Explicit isolated-lab acknowledgment required'
[[ $snapshot =~ ^[a-zA-Z0-9._:-]{1,120}$ ]] || fail 'A user-confirmed snapshot reference is required'
[[ -n $evidence ]] || fail 'An evidence directory is required'
for command in awk bash cat cmp date dpkg dpkg-deb dpkg-query du grep head id install journalctl mkdir ps readlink realpath sed sha256sum sleep ss stat systemctl systemd-analyze systemd-detect-virt tee timeout tr; do
  command -v "$command" >/dev/null || fail "Missing VM test prerequisite: $command"
done
[[ $(awk -F= '$1=="ID"{gsub(/"/,"",$2);print $2}' /etc/os-release) == debian ]] || fail 'Debian is required'
[[ $(awk -F= '$1=="VERSION_ID"{gsub(/"/,"",$2);print $2}' /etc/os-release) =~ ^13([.][0-9]+)?$ ]] || fail 'Debian 13 is required'
[[ $(dpkg --print-architecture) == amd64 ]] || fail 'amd64 is required'
[[ $(readlink -f /proc/1/exe) == */systemd ]] || fail 'systemd must be PID 1'
[[ $(systemd-detect-virt --vm) == vmware ]] || fail 'This contract is scoped to the VMware lab'
[[ -r /etc/machine-id && -r /proc/sys/kernel/random/boot_id ]] || fail 'Machine and boot identity are required'

readonly package=andeiva-experimental unit=andeiva-api.service config=/etc/andeiva/andeiva-api.env
readonly api=/usr/lib/andeiva/andeiva-api cli=/usr/bin/andeiva custom_port=44001 default_port=4000
script_dir=$(realpath -e -- "$(dirname -- "${BASH_SOURCE[0]}")")
source_root=$(realpath -e -- "$script_dir/../../..")
evidence=$(realpath -m -- "$evidence")
if [[ -f $source_root/go.mod ]]; then
  case "$evidence/" in "$source_root/"*) fail 'Evidence must be outside the source tree';; esac
fi
case "$evidence/" in "$script_dir/"*) fail 'Evidence must be outside the test source directory';; esac
[[ $evidence != / ]] || fail 'Invalid evidence location'
# Parent directories must not let another user replace root-owned test state.
parent=$(dirname -- "$evidence")
while [[ $parent != / ]]; do
  [[ -d $parent && $(stat -c %u "$parent") == 0 ]] || fail 'Evidence parents must be root-owned'
  permissions=$(stat -c %a "$parent")
  (( (8#$permissions & 0022) == 0 || (8#$permissions & 01000) != 0 )) || fail 'Writable evidence parent lacks sticky protection'
  parent=$(dirname -- "$parent")
done
owned=false

assert_no_listener() {
  [[ -z $(ss -H -ltn "sport = :$1") ]] || fail "Unexpected TCP listener on port $1"
}
installed_version() { dpkg-query --show --showformat='${Version}' "$package"; }
file_hash() { sha256sum -- "$1" | awk '{print $1}'; }
check_field() {
  [[ $(dpkg-deb --field "$1" "$2") == "$3" ]] || fail "Unexpected package field $2"
}
stage_package() {
  local source=$1 expected=$2 version=$3 name=$4 staged
  [[ $expected =~ ^[a-fA-F0-9]{64}$ ]] || fail 'An expected SHA256 from the static package check is required'
  source=$(realpath -e -- "$source")
  [[ -f $source && $(stat -c %s -- "$source") -le 104857600 ]] || fail 'Unexpected package file or size'
  staged="$evidence/$name.deb"
  install -m 600 -- "$source" "$staged"
  [[ $(file_hash "$staged") == "${expected,,}" ]] || fail 'Package hash mismatch'
  check_field "$staged" Package "$package"
  check_field "$staged" Architecture amd64
  check_field "$staged" Version "$version"
  dpkg-deb --contents "$staged" > "$evidence/$name-contents.txt"
  printf '%s\n' "$staged"
}
record_failure() {
  local code=$?
  trap - EXIT
  if [[ $code != 0 && $owned == true ]]; then
    systemctl stop "$unit" || true
    journalctl --unit "$unit" --no-pager --lines 150 > "$evidence/failure-journal.txt" 2>&1 || true
    printf 'Failure retained for inspection; restore the confirmed snapshot if recovery is needed.\n' >&2
  fi
  exit "$code"
}
trap record_failure EXIT

http_check() {
  local port=$1 method=$2 path=$3 expected_status=$4 expected_body=$5 label=$6 response
  [[ $port == "$default_port" || $port == "$custom_port" ]] || fail 'HTTP test port is outside the contract'
  response="$evidence/$label.http"
  # Constant loopback target and parameterized fixed grammar; no curl, proxy or DNS dependency.
  timeout 4 bash -c '
    exec 3<>"/dev/tcp/127.0.0.1/$1"
    printf "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" "$2" "$3" >&3
    head -c 8192 <&3
  ' _ "$port" "$method" "$path" > "$response" || fail "HTTP test failed: $label"
  [[ $(head -n 1 "$response" | tr -d '\r') == "HTTP/1.1 $expected_status "* ]] || fail "Wrong HTTP status: $label"
  [[ $(tr -d '\r' < "$response" | sed '1,/^$/d') == "$expected_body" ]] || fail "Wrong HTTP body: $label"
}
wait_healthy() {
  local port=$1
  for attempt in {1..50}; do
    if ANDEIVA_LISTEN_ADDR="127.0.0.1:$port" "$api" --healthcheck >/dev/null 2>&1; then return; fi
    sleep 0.2
  done
  fail 'Local process health did not become ready'
}
assert_property() {
  [[ $(systemctl show "$unit" --property "$1" --value) == "$2" ]] || fail "Unexpected effective property $1"
}
check_service() {
  local port=$1 label=$2 pid uid listeners
  systemctl is-active --quiet "$unit" || fail 'Service is not active'
  wait_healthy "$port"
  pid=$(systemctl show "$unit" --property MainPID --value)
  [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/status ]] || fail 'Missing service process'
  uid=$(awk '/^Uid:/{print $2}' "/proc/$pid/status")
  [[ $uid =~ ^[1-9][0-9]*$ ]] || fail 'Service runs as root'
  [[ $(awk '/^NoNewPrivs:/{print $2}' "/proc/$pid/status") == 1 ]] || fail 'NoNewPrivileges not effective'
  [[ $(awk '/^CapEff:/{print $2}' "/proc/$pid/status") == 0000000000000000 ]] || fail 'Effective capabilities not empty'
  assert_property DynamicUser yes
  assert_property NoNewPrivileges yes
  assert_property ProtectSystem strict
  assert_property ProtectHome yes
  assert_property PrivateTmp yes
  assert_property PrivateDevices yes
  assert_property CapabilityBoundingSet ''
  assert_property AmbientCapabilities ''
  assert_property MemoryMax 134217728
  assert_property TasksMax 64
  assert_property CPUQuotaPerSecUSec 1s
  [[ -d /run/andeiva-api && ! -L /run/andeiva-api ]] || fail 'Missing or unsafe runtime directory'
  [[ $(stat -c %a /run/andeiva-api) == 750 ]] || fail 'Unexpected runtime directory mode'
  [[ $(stat -c %u /run/andeiva-api) == "$uid" ]] || fail 'Runtime directory has wrong owner'
  [[ ! -e /var/lib/andeiva && ! -e /var/lib/andeiva-api ]] || fail 'Unexpected persistent state'
  listeners=$(ss -H -ltnp | awk -v pid="$pid" 'index($0,"pid=" pid ",") {print}')
  [[ $(printf '%s\n' "$listeners" | grep -c .) == 1 ]] || fail 'Expected exactly one service TCP listener'
  [[ $(printf '%s\n' "$listeners" | awk '{print $4}') == "127.0.0.1:$port" ]] || fail 'Service listener is not loopback-only'
  printf '%s\n' "$listeners" > "$evidence/$label-listeners.txt"
  systemctl show "$unit" > "$evidence/$label-systemd.txt"
  http_check "$port" GET /healthz 200 '{"status":"ok"}' "$label-health"
  http_check "$port" GET /api/config 404 '{"code":"ANDEIVA_NOT_FOUND"}' "$label-management-negative"
  http_check "$port" POST /healthz 405 '{"code":"ANDEIVA_METHOD_NOT_ALLOWED"}' "$label-method-negative"
  "$cli" --lang en status
  "$cli" --lang es status
  "$cli" --lang pt status
  if "$cli" config > "$evidence/$label-cli-negative.txt" 2>&1; then fail 'Unimplemented CLI command succeeded'; fi
}
measure() {
  local label=$1 before after wall_before wall_after pid current_pid
  pid=$(systemctl show "$unit" --property MainPID --value)
  before=$(systemctl show "$unit" --property CPUUsageNSec --value)
  wall_before=$(date +%s%N)
  sleep 3
  after=$(systemctl show "$unit" --property CPUUsageNSec --value)
  wall_after=$(date +%s%N)
  current_pid=$(systemctl show "$unit" --property MainPID --value)
  [[ $pid == "$current_pid" && $pid != 0 ]] || fail 'Service restarted during the measurement'
  [[ $before =~ ^[0-9]+$ && $after =~ ^[0-9]+$ ]] || fail 'CPU accounting unavailable'
  (( after >= before && wall_after > wall_before )) || fail 'Invalid measurement interval'
  {
    printf 'scope=development_scaffold_sample_not_appliance_benchmark\n'
    printf 'cpu_before_nsec=%s\ncpu_after_nsec=%s\nwall_before_nsec=%s\nwall_after_nsec=%s\n' "$before" "$after" "$wall_before" "$wall_after"
    awk -v a="$before" -v b="$after" -v start="$wall_before" -v end="$wall_after" 'BEGIN {printf "cpu_percent_one_core=%.6f\n",100*(b-a)/(end-start)}'
    awk '/^(VmRSS|VmHWM):/{print}' "/proc/$pid/status"
    systemctl show "$unit" --property MemoryCurrent --property MemoryPeak --property CPUUsageNSec
    du -sb -- "$cli" /usr/lib/andeiva /usr/share/doc/andeiva-experimental /etc/andeiva /run/andeiva-api
  } > "$evidence/$label-resources.txt"
}
set_port() {
  [[ -f $config && ! -L $config ]] || fail 'Unsafe conffile'
  printf 'ANDEIVA_LISTEN_ADDR=127.0.0.1:%s\n' "$custom_port" > "$evidence/custom.env"
  install -m 644 -- "$evidence/custom.env" "$config"
}
assert_purged() {
  systemctl daemon-reload
  assert_no_listener "$default_port"
  assert_no_listener "$custom_port"
  for path in "$cli" /usr/lib/andeiva /usr/lib/systemd/system/andeiva-api.service "$config" /run/andeiva-api /usr/share/doc/andeiva-experimental; do
    [[ ! -e $path && ! -L $path ]] || fail "Package path remained after purge: $path"
  done
  [[ $(systemctl show "$unit" --property LoadState --value) == not-found ]] || fail 'Unit remains loaded after purge'
}
assert_reboot_ownership() {
  [[ -d $evidence && ! -L $evidence && $(stat -c %u "$evidence") == 0 && $(stat -c %a "$evidence") == 700 ]] || fail 'Invalid root-owned reboot evidence directory'
  for file in suite.marker machine-id boot-id snapshot-ref installed-version api.sha256 cli.sha256 env.sha256 phase; do
    [[ -f $evidence/$file && ! -L $evidence/$file && $(stat -c %u "$evidence/$file") == 0 && $(stat -c %a "$evidence/$file") == 600 ]] || fail 'Invalid reboot ownership state'
  done
  [[ $(cat "$evidence/suite.marker") == ANDEIVA-NATIVE-LIFECYCLE-V1 ]] || fail 'Unknown state format'
  cmp -s /etc/machine-id "$evidence/machine-id" || fail 'Evidence belongs to another machine'
  [[ $(cat "$evidence/snapshot-ref") == "$snapshot" ]] || fail 'Snapshot confirmation reference differs'
  [[ $(installed_version) == "$(cat "$evidence/installed-version")" ]] || fail 'Installed package changed since test preparation'
  [[ $(file_hash "$api") == "$(cat "$evidence/api.sha256")" && $(file_hash "$cli") == "$(cat "$evidence/cli.sha256")" && $(file_hash "$config") == "$(cat "$evidence/env.sha256")" ]] || fail 'Test-owned installed files changed; refusing lifecycle mutation'
}

if [[ $mode == verify-after-reboot || $mode == cleanup-reboot ]]; then
  [[ -z $install_deb && -z $install_hash && -z $upgrade_deb && -z $upgrade_hash ]] || fail 'Reboot follow-up does not accept new packages'
  assert_reboot_ownership
  exec > >(tee -a "$evidence/follow-up.txt") 2>&1
  if [[ $mode == verify-after-reboot ]]; then
    [[ $(cat /proc/sys/kernel/random/boot_id) != "$(cat "$evidence/boot-id")" ]] || fail 'A real reboot has not occurred'
    owned=true
    systemctl is-enabled --quiet "$unit" || fail 'Service is not enabled after reboot'
    check_service "$default_port" after-reboot
    measure after-reboot
    printf 'verified-after-reboot\n' > "$evidence/phase"
    printf 'PASS: real reboot observed; test package retained until cleanup-reboot.\n'
  else
    owned=true
    systemctl stop "$unit"
    dpkg --purge "$package"
    assert_purged
    owned=false
    printf 'cleaned\n' > "$evidence/phase"
    printf 'PASS: test-owned reboot package purged.\n'
  fi
  exit 0
fi

[[ -n $install_deb && -n $install_hash ]] || fail 'Install package and hash required'
if [[ $mode == run ]]; then [[ -n $upgrade_deb && -n $upgrade_hash ]] || fail 'Upgrade package and hash required';
else [[ -z $upgrade_deb && -z $upgrade_hash ]] || fail 'Reboot preparation takes one package only'; fi
[[ ! -e $evidence && ! -L $evidence ]] || fail 'Evidence directory must be new'
if dpkg-query --show "$package" >/dev/null 2>&1; then fail 'A previous package record exists; test will not overwrite it'; fi
[[ $(systemctl show "$unit" --property LoadState --value) == not-found ]] || fail 'A pre-existing unit exists'
[[ ! -e /usr/sbin/policy-rc.d && ! -L /usr/sbin/policy-rc.d ]] || fail 'Existing service-start policy requires a separate reviewed test; not modified here'
for path in "$cli" /usr/lib/andeiva /etc/andeiva /run/andeiva-api /var/lib/andeiva /var/lib/andeiva-api /usr/share/doc/andeiva-experimental /usr/lib/systemd/system/andeiva-api.service /etc/systemd/system/andeiva-api.service /etc/systemd/system/andeiva-api.service.d /etc/systemd/system/multi-user.target.wants/andeiva-api.service; do
  [[ ! -e $path && ! -L $path ]] || fail "Pre-existing package/service path: $path"
done
assert_no_listener "$default_port"
assert_no_listener "$custom_port"
mkdir -m 700 -- "$evidence"
exec > >(tee "$evidence/lifecycle.txt") 2>&1
printf 'snapshot_confirmation_reference=%s\n' "$snapshot"
printf 'No snapshot operation or appliance benchmark is performed by this suite.\n'
install_deb=$(stage_package "$install_deb" "$install_hash" '0.0.0~exp1' install)
if [[ $mode == run ]]; then upgrade_deb=$(stage_package "$upgrade_deb" "$upgrade_hash" '0.0.0~exp2' upgrade); fi
owned=true
dpkg --install "$install_deb"
[[ $(installed_version) == '0.0.0~exp1' ]] || fail 'Unexpected installed version'
systemctl is-enabled --quiet "$unit" || fail 'Package did not enable the service'
systemd-analyze verify --man=no /usr/lib/systemd/system/andeiva-api.service
check_service "$default_port" initial
measure initial

if [[ $mode == prepare-reboot ]]; then
  printf 'ANDEIVA-NATIVE-LIFECYCLE-V1\n' > "$evidence/suite.marker"
  cat /etc/machine-id > "$evidence/machine-id"
  cat /proc/sys/kernel/random/boot_id > "$evidence/boot-id"
  printf '%s\n' "$snapshot" > "$evidence/snapshot-ref"
  installed_version > "$evidence/installed-version"
  file_hash "$api" > "$evidence/api.sha256"
  file_hash "$cli" > "$evidence/cli.sha256"
  file_hash "$config" > "$evidence/env.sha256"
  printf 'awaiting-reboot\n' > "$evidence/phase"
  printf 'PREPARED: reboot was not performed. After an authorized reboot run verify-after-reboot, then cleanup-reboot.\n'
  exit 0
fi

systemctl stop "$unit"
assert_no_listener "$default_port"
[[ ! -e /run/andeiva-api ]] || fail 'Runtime directory remained after stop'
systemctl reset-failed "$unit"
systemctl start "$unit"
check_service "$default_port" start
systemctl reset-failed "$unit"
systemctl restart "$unit"
check_service "$default_port" restart

set_port
systemctl reset-failed "$unit"
systemctl restart "$unit"
assert_no_listener "$default_port"
check_service "$custom_port" custom-port
systemctl reset-failed "$unit"
dpkg --force-confold --install "$upgrade_deb"
[[ $(installed_version) == '0.0.0~exp2' ]] || fail 'Upgrade version mismatch'
cmp -s "$config" "$evidence/custom.env" || fail 'Upgrade replaced the modified conffile'
check_service "$custom_port" upgrade
measure upgrade

# Downgrade is explicit and restricted to the verified experimental package pair.
systemctl reset-failed "$unit"
dpkg --force-downgrade --force-confold --install "$install_deb"
[[ $(installed_version) == '0.0.0~exp1' ]] || fail 'Rollback version mismatch'
cmp -s "$config" "$evidence/custom.env" || fail 'Rollback replaced the modified conffile'
check_service "$custom_port" rollback

# Updates must preserve an operator's disabled or masked service state.
systemctl disable --now "$unit"
dpkg --force-confold --install "$upgrade_deb"
[[ $(systemctl is-enabled "$unit" || true) == disabled ]] || fail 'Upgrade re-enabled an operator-disabled service'
if systemctl is-active --quiet "$unit"; then fail 'Upgrade started an operator-disabled service'; fi
assert_no_listener "$custom_port"
systemctl mask "$unit"
dpkg --force-downgrade --force-confold --install "$install_deb"
[[ $(systemctl is-enabled "$unit" || true) == masked ]] || fail 'Rollback removed an operator mask'
if systemctl is-active --quiet "$unit"; then fail 'Rollback started an operator-masked service'; fi
assert_no_listener "$custom_port"
cmp -s "$config" "$evidence/custom.env" || fail 'Disabled/masked update changed the conffile'
systemctl unmask "$unit"
systemctl enable "$unit"
systemctl reset-failed "$unit"
systemctl start "$unit"
check_service "$custom_port" unmasked

# Simulate a process crash, not a machine power loss, and observe bounded recovery.
previous_pid=$(systemctl show "$unit" --property MainPID --value)
systemctl kill --kill-whom=main --signal=SIGKILL "$unit"
recovered=false
for attempt in {1..75}; do
  current_pid=$(systemctl show "$unit" --property MainPID --value)
  if [[ $current_pid =~ ^[1-9][0-9]*$ && $current_pid != "$previous_pid" ]] && systemctl is-active --quiet "$unit"; then
    recovered=true
    break
  fi
  sleep 0.2
done
[[ $recovered == true ]] || fail 'Service did not restart after the deliberate process crash'
printf 'previous_pid=%s\nrestarted_pid=%s\n' "$previous_pid" "$current_pid" > "$evidence/crash-recovery.txt"
check_service "$custom_port" crash-recovery
systemctl reset-failed "$unit"

printf 'ANDEIVA_LISTEN_ADDR=invalid-address\n' > "$evidence/invalid.env"
install -m 644 -- "$evidence/invalid.env" "$config"
if systemctl restart "$unit"; then fail 'Invalid address unexpectedly produced a successful service start'; fi
assert_no_listener "$custom_port"
assert_no_listener "$default_port"
systemctl reset-failed "$unit"
if dpkg --force-confold --install "$upgrade_deb"; then fail 'Invalid configuration unexpectedly completed package configuration'; fi
[[ $(dpkg-query --show --showformat='${Status}' "$package") == 'install ok half-configured' ]] || fail 'Expected half-configured package after service startup failure'
assert_no_listener "$custom_port"
assert_no_listener "$default_port"
systemctl stop "$unit"
systemctl reset-failed "$unit"
install -m 644 -- "$evidence/custom.env" "$config"
dpkg --configure "$package"
[[ $(dpkg-query --show --showformat='${Status}' "$package") == 'install ok installed' ]] || fail 'Package configuration did not recover'
check_service "$custom_port" recovered

dpkg --remove "$package"
assert_no_listener "$custom_port"
[[ ! -e $api && ! -e $cli ]] || fail 'Executables remained after remove'
cmp -s "$config" "$evidence/custom.env" || fail 'Remove did not preserve the conffile'
dpkg --purge "$package"
assert_purged
dpkg --install "$install_deb"
check_service "$default_port" reinstall
dpkg --purge "$package"
assert_purged
owned=false
printf 'PASS: installation, lifecycle, upgrade, explicit rollback, disabled/masked preservation, process crash recovery, negative configuration, remove/purge/reinstall.\n'
printf 'Real reboot remains a separate prepare/verify/cleanup gate; no appliance benchmark claim.\n'

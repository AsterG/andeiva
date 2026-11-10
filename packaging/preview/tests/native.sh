#!/usr/bin/env bash
# Run only on the authorized Debian VM after installation and provisioning.
# Default: observations only. Optional flags interrupt the preview service.
# Evidence is private, root-readable, and is never removed by this script.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 077

usage() {
  cat <<'EOF'
Usage: native.sh --ack-isolated-debian13-vm [--lifecycle] [--api-failure]
Requires root, Debian 13 AMD64, systemd, jq and an already healthy preview.
--lifecycle   Stop the complete preview, check owned cleanup, then start it.
--api-failure Kill only the API main process; check its automatic recovery.
No reboot, provisioning, rule mutation, helper kill or host network change.
Use a recoverable laboratory snapshot. Review outstanding transactions first.
EOF
}
ack=false lifecycle=false api_failure=false
for arg in "$@"; do
  case "$arg" in
    --ack-isolated-debian13-vm) ack=true ;;
    --lifecycle) lifecycle=true ;;
    --api-failure) api_failure=true ;;
    --help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$ack" == true && $EUID == 0 ]] || { usage >&2; exit 2; }
[[ -r /etc/os-release && -d /run/systemd/system ]]
# This is the distribution-owned identity file, not caller-supplied input.
. /etc/os-release
[[ "$ID" == debian && "$VERSION_ID" == 13 && $(dpkg --print-architecture) == amd64 ]]
for command in jq ip nft systemctl timeout stat cmp mktemp du date; do
  command -v "$command" >/dev/null || { echo "Missing prerequisite: $command" >&2; exit 2; }
done
binary=/usr/lib/andeiva-preview/andeiva-preview
[[ -x "$binary" && ! -L "$binary" && $(stat -c %u "$binary") == 0 ]]
[[ $(stat -c %a "$binary") =~ ^[0-7]?[0-7][0145][0145]$ ]]
[[ $(stat -Lc %i /proc/self/ns/net) == $(stat -Lc %i /proc/1/ns/net) ]]
units=(andeiva-preview-namespaces.service andeiva-preview-helper.service andeiva-preview-api.service)
all_units=("${units[@]}" andeiva-preview-api.socket andeiva-preview.target)
for unit in "${all_units[@]}"; do systemctl is-active --quiet "$unit"; done

evidence=$(mktemp -d /var/tmp/andeiva-preview-acceptance.XXXXXXXX)
printf 'Private evidence: %s\n' "$evidence"
events="$evidence/events.jsonl"
: > "$events"
baseline_ready=false
stage=initial
event() {
  jq -nc --arg at "$(date -u +%FT%TZ)" --arg stage "$stage" --arg result "$1" \
    '{at:$at,stage:$stage,result:$result}' >> "$events"
}

snapshot_host() {
  local prefix=$1
  ip -j address show > "$evidence/$prefix-addresses.raw.json" || return 1
  ip -j -4 route show table all > "$evidence/$prefix-routes4.raw.json" || return 1
  ip -j -6 route show table all > "$evidence/$prefix-routes6.raw.json" || return 1
  ip -j -4 rule show > "$evidence/$prefix-rules4.json" || return 1
  ip -j -6 rule show > "$evidence/$prefix-rules6.json" || return 1
  nft -j list ruleset > "$evidence/$prefix-nft.raw.json" || return 1
  # Lease/route lifetimes and packet counters advance without policy changes.
  jq -S 'walk(if type=="object" then del(.valid_life_time,.preferred_life_time) else . end)' \
    "$evidence/$prefix-addresses.raw.json" > "$evidence/$prefix-addresses.json" || return 1
  for family in 4 6; do
    jq -S 'walk(if type=="object" then del(.expires) else . end)' \
      "$evidence/$prefix-routes$family.raw.json" > "$evidence/$prefix-routes$family.json" || return 1
  done
  jq -S '.nftables |= map(select(has("metainfo")|not)) | walk(
    if type=="object" and has("counter") and (.counter|type)=="object"
    then .counter |= del(.packets,.bytes) else . end)' \
    "$evidence/$prefix-nft.raw.json" > "$evidence/$prefix-nft.json" || return 1
  jq -n --arg ipv4 "$(cat /proc/sys/net/ipv4/ip_forward)" \
    --arg ipv6 "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" \
    '{ipv4_forwarding:$ipv4,ipv6_forwarding:$ipv6}' > "$evidence/$prefix-forwarding.json"
}
compare_host() {
  local prefix=$1 suffix
  for suffix in addresses routes4 routes6 rules4 rules6 nft forwarding; do
    cmp -s "$evidence/before-$suffix.json" "$evidence/$prefix-$suffix.json" || return 1
  done
}
finish() {
  local rc=$? invariant=false
  trap - EXIT
  set +e
  if [[ "$baseline_ready" == true ]]; then
    snapshot_host after
    if [[ $? == 0 ]] && compare_host after; then invariant=true; else rc=1; fi
  fi
  jq -s --argjson exit_code "$rc" --argjson host_unchanged "$invariant" \
    --argjson lifecycle "$lifecycle" --argjson api_failure "$api_failure" \
    '{schema_version:1,exit_code:$exit_code,host_unchanged:$host_unchanged,
      requested:{lifecycle:$lifecycle,api_failure:$api_failure},events:.,
      limitations:["Probe outcomes are observations; no expected policy is inferred.",
        "This harness does not prove Web/CLI/API parity, RBAC or transaction correctness.",
        "Cleanup checks owned paths and units, not global absence of namespace references.",
        "No reboot, power-loss or helper-failure test is performed.",
        "CPU and memory are cgroup observations, not a production capacity benchmark."]}' \
      "$events" > "$evidence/report.json"
  printf 'Result: %s; private report: %s/report.json\n' "$rc" "$evidence"
  exit "$rc"
}
trap finish EXIT
trap 'event failed' ERR

health() {
  timeout 10 "$binary" health > "$evidence/$1-health.json"
  jq -e '.available == true' "$evidence/$1-health.json" >/dev/null
}
probes() {
  local label=$1 protocol port
  for protocol in tcp udp; do
    for port in 18080 18081 18082; do
      timeout 12 "$binary" probe --protocol "$protocol" --port "$port" \
        > "$evidence/$label-$protocol-$port.json"
      jq -e '.healthy == true and (.allowed|type) == "boolean" and .error == null' \
        "$evidence/$label-$protocol-$port.json" >/dev/null
    done
  done
}
resources() {
  local label=$1 unit
  : > "$evidence/$label-resources.jsonl"
  for unit in "${units[@]}"; do
    systemctl show "$unit" --property=MainPID,MemoryCurrent,MemoryPeak,CPUUsageNSec,TasksCurrent,ActiveEnterTimestampMonotonic \
      | jq -Rn --arg unit "$unit" '[inputs | split("=") | {key:.[0],value:.[1]}] | from_entries | {unit:$unit,observed:.}' \
      >> "$evidence/$label-resources.jsonl"
  done
  jq -s '.' "$evidence/$label-resources.jsonl" > "$evidence/$label-resources.json"
}

snapshot_host before
baseline_ready=true
health initial
event passed
stage=probes
probes initial
event observed
stage=resources
resources sample-start
sample_start=$(date +%s%N)
sleep 2
resources sample-end
sample_end=$(date +%s%N)
jq -n --slurpfile start "$evidence/sample-start-resources.json" \
  --slurpfile end "$evidence/sample-end-resources.json" \
  --argjson duration_ns "$((sample_end-sample_start))" \
  '{duration_ns:$duration_ns,units:[$end[0][] as $e | $start[0][] | select(.unit==$e.unit) |
    {unit:.unit,memory_bytes:(try ($e.observed.MemoryCurrent|tonumber) catch null),
     cpu_delta_ns:((try ($e.observed.CPUUsageNSec|tonumber) catch null) as $b |
       (try (.observed.CPUUsageNSec|tonumber) catch null) as $a |
       if $a != null and $b != null and $b >= $a then $b-$a else null end)}]}' \
  > "$evidence/resource-sample.json"
du -sx --block-size=1 /var/lib/andeiva-preview /usr/lib/andeiva-preview /usr/share/andeiva-preview \
  > "$evidence/disk-allocated-bytes.txt"
event observed

if [[ "$api_failure" == true ]]; then
  stage=api-failure
  previous_pid=$(systemctl show --value --property=MainPID andeiva-preview-api.service)
  [[ "$previous_pid" =~ ^[1-9][0-9]*$ ]]
  systemctl kill --kill-whom=main --signal=SIGKILL andeiva-preview-api.service
  recovered=false
  for ((attempt=0; attempt<30; attempt++)); do
    sleep 1
    current_pid=$(systemctl show --value --property=MainPID andeiva-preview-api.service)
    if [[ "$current_pid" =~ ^[1-9][0-9]*$ && "$current_pid" != "$previous_pid" ]] \
      && health recovered 2>/dev/null; then recovered=true; break; fi
  done
  [[ "$recovered" == true ]]
  probes recovered
  event passed
fi

if [[ "$lifecycle" == true ]]; then
  stage=stop-cleanup
  timeout 90 systemctl stop andeiva-preview.target
  # ExecStopPost may enqueue dependent stop jobs after the target job returns.
  stopped=false
  for ((attempt=0; attempt<90; attempt++)); do
    stopped=true
    for unit in "${all_units[@]}"; do
      [[ $(systemctl show --value --property=ActiveState "$unit") == inactive ]] || stopped=false
    done
    [[ "$stopped" == true ]] && break
    sleep 1
  done
  [[ "$stopped" == true ]]
  for path in /run/andeiva-preview/runtime.json /run/andeiva-preview/runtime.pending \
    /run/andeiva-preview/netns/gateway /run/andeiva-preview/control.sock \
    /run/andeiva-preview-helper/helper.sock /run/andeiva-preview-api/health.sock; do
    [[ ! -e "$path" && ! -L "$path" ]]
  done
  snapshot_host stopped
  compare_host stopped
  event passed
  stage=start
  start_ns=$(date +%s%N)
  timeout 90 systemctl start andeiva-preview.target
  health restarted
  end_ns=$(date +%s%N)
  jq -n --argjson elapsed_ns "$((end_ns-start_ns))" '{target_start_to_health_ns:$elapsed_ns}' \
    > "$evidence/start-time.json"
  probes restarted
  event passed
fi
stage=complete
event passed

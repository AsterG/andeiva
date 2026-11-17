#!/usr/bin/env bash
# Unprivileged coordinator/store qualification; no host network or native boot.
set -euo pipefail
umask 077
export LC_ALL=C
[[ $# == 0 && $(uname -s) == Linux ]] || exit 64
task_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
task_directory=$(mktemp -d "${TMPDIR:-/tmp}/andeiva-routed-persistence.XXXXXXXX")
cleanup() {
  local task_status=$?
  trap - EXIT
  rm -f -- "$task_directory/result.log" || task_status=1
  rmdir -- "$task_directory" || task_status=1
  exit "$task_status"
}
trap cleanup EXIT
task_tests=(
  TestCoordinatorV2LifecycleAndIndependentProjections
  TestCoordinatorV2AutomaticTimeoutWithoutAdministrator
  TestCoordinatorV2RejectsWrongConfirmationAndGlobalTargets
  TestCoordinatorV2RestartRevertsUnconfirmedWithImmutableOutcome
  TestCoordinatorV2RollbackRequiresVerifiedHistory
  TestV2BootStartupAndProcessRestart
  TestV2BootProcessExitWithPersistentSimulatedEngines
  TestNoServicesV3StageReplaceCommitRetainExactRollback
  TestNoServicesV3DHCPCommitUsesOnlyLANInventory
  TestRoutedFreshScopeV3ServiceRestartKeepsRunningDenyAndStartupAllow
  TestRoutedBootTargetPreservesStaleCandidateWithoutRebasing
  TestRoutedOSBootBoundaryPendingSelectsStartupWithoutRearmingOldLease
  TestRoutedOSBootBoundarySameBootForeignRolesAreRefused
  TestRoutedRebootScopeV4RetiresDHCPBeforeLANBootWithoutOldClockReuse
  TestRoutedRebootScopeV4UsesStartupInsteadOfRunning
  TestRoutedRebootScopeV4RejectsUnprovenScopeWithoutEffects
)
task_pattern=$(IFS='|'; printf '^(%s)$' "${task_tests[*]}")
cd -- "$task_root"
# Bound evidence without applying RLIMIT_FSIZE to the store fault tests.
if go test -race ./internal/configpoc -count=1 -timeout=5m -v -run "$task_pattern" 2>&1 |
  awk '{ size += length($0)+1; if (size > 1048576) exit 70; print }' > "$task_directory/result.log"; then
  :
else
  task_status=$?
  cat -- "$task_directory/result.log"
  exit "$task_status"
fi
cat -- "$task_directory/result.log"
for task_test in "${task_tests[@]}"; do
  awk -v name="$task_test" '
    $0 == "=== RUN   " name { runs++ }
    $1 == "---" && $2 == "PASS:" && $3 == name { passes++ }
    END { exit !(runs == 1 && passes == 1) }
  ' "$task_directory/result.log"
done
awk '
  /(^|[[:space:]])--- (SKIP|FAIL):|^FAIL|no tests to run/ { bad=1 }
  $0 == "PASS" { passes++ }
  END { exit (bad || passes != 1) }
' "$task_directory/result.log"
printf '%s\n' 'ANDEIVA_ROUTED_PERSISTENCE_QUALIFICATION=pass'

package configpoc

func preservesRecoveryReserveV2(previous, next v2State) bool {
	if previous.RecoveryReserveVersion > 1 || next.RecoveryReserveVersion > 1 || next.RecoveryReserveVersion < previous.RecoveryReserveVersion || (previous.ReserveArchiveRoot != "" && next.ReserveArchiveRoot == "") {
		return false
	}
	if reserveArchiveFrozenV2(previous) && previous.ReserveArchiveRoot != next.ReserveArchiveRoot {
		return false
	}
	return true
}

func reserveArchiveFrozenV2(state v2State) bool {
	cfg := state.Configuration
	return state.RecoveryReserveVersion == 1 && cfg != nil && (cfg.Intent != nil || cfg.Pending != nil || cfg.RecoveryRequired)
}

// Selection comparisons retain flags and the small immutable timed scope,
// never another copy of configuration payloads or traversable root objects.
func reserveFreezeSummaryV2(cfg *v2Configuration) *v2Configuration {
	if cfg == nil {
		return nil
	}
	summary := &v2Configuration{RecoveryRequired: cfg.RecoveryRequired}
	if cfg.Intent != nil {
		summary.Intent = &v2CoordinatorIntent{}
		if cfg.Intent.RoutedWork != "" {
			in := *cfg.Intent
			summary.Intent = &in
		}
		if cfg.Intent.GuardDeadline != nil {
			in := *cfg.Intent
			deadline := *in.GuardDeadline
			in.GuardDeadline = &deadline
			summary.Intent = &in
		}
	}
	if cfg.Pending != nil {
		summary.Pending = &v2Confirmation{}
	}
	return summary
}

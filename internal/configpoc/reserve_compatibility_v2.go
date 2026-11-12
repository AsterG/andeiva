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

// A selection-chain comparison needs only these flags, not another retained
// copy of complete configuration payloads from every predecessor.
func reserveFreezeSummaryV2(cfg *v2Configuration) *v2Configuration {
	if cfg == nil {
		return nil
	}
	summary := &v2Configuration{RecoveryRequired: cfg.RecoveryRequired}
	if cfg.Intent != nil {
		summary.Intent = &v2CoordinatorIntent{}
	}
	if cfg.Pending != nil {
		summary.Pending = &v2Confirmation{}
	}
	return summary
}

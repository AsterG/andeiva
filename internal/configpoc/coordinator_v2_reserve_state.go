package configpoc

func reserveHeldReservationsV2(st v2State) (uint64, bool) {
	if st.RecoveryReserveVersion == 0 {
		return 0, len(st.ActiveReserves) == 0 && st.SystemBundle == nil
	}
	if st.RecoveryReserveVersion != 1 || len(st.ActiveReserves) > 16 {
		return 0, false
	}
	seen := map[string]bool{}
	var held uint64
	for _, active := range st.ActiveReserves {
		if active.Work == "" || seen[active.Work] || !validReserveBundleV2(active.Bundle) || active.Bundle.Scope.Kind != "operation" || reserveWorkV2(active.Bundle) != active.Work {
			return 0, false
		}
		seen[active.Work] = true
		open := false
		for _, ns := range st.Namespaces {
			for _, id := range namespaceOpenIDsV2(ns) {
				if id == active.Work {
					open = true
				}
			}
		}
		if active.CanonicalHeld {
			if open || active.Bundle.Claims.Admission.Slot >= 8 {
				return 0, false
			}
			held++
		}
	}
	if active := st.SystemBundle; active != nil {
		if active.Work == "" || !validReserveBundleV2(active.Bundle) || active.Bundle.Scope.Kind == "operation" || reserveWorkV2(active.Bundle) != active.Work || seen[active.Work] {
			return 0, false
		}
		if active.CanonicalHeld {
			if st.Configuration != nil && st.Configuration.Intent != nil && st.Configuration.Intent.Operation == active.Work {
				return 0, false
			}
			held++
		}
	}
	return held, true
}

func holdReserveCanonicalV2(st *v2State, op v2Operation) bool {
	if st.RecoveryReserveVersion != 1 || op.Reserve == nil {
		return false
	}
	if i := reserveActiveIndexV2(st, op.ID); i >= 0 && reserveJSONEqualV2(st.ActiveReserves[i].Bundle, op.Reserve) {
		st.ActiveReserves[i].CanonicalHeld = true
	}
	return true
}

func (s *v2Store) reserveBeforeAdmissionV2() error {
	if s.state.RecoveryReserveVersion != 1 || s.reserves == nil {
		return nil
	}
	return s.reserves.maintain(s)
}

func (s *v2Store) reserveAdmissionV2(st *v2State, op *v2Operation) error {
	if s.state.RecoveryReserveVersion != 1 || s.reserves == nil {
		return nil
	}
	return s.reserves.prepareAdmission(s, st, op)
}

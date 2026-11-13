package configpoc

import "github.com/AsterG/andeiva/internal/recoveryreserve"

func validateRoutedDHCPTerminalV3(d v3RoutedDHCPState, lineage string, load func(string, any) error) error {
	w, err := loadRoutedDHCPWorkV3(d.Work, lineage, load)
	if err != nil || !routedDHCPTerminalV3(&d) || !validHash(d.Audit) || !validReserveBundleV2(d.Bundle) || d.Bundle.Scope.Kind != "recovery" || d.Bundle.Scope.Domain != "routed" || d.Bundle.Scope.Lineage != lineage || d.Bundle.Scope.Fingerprint != d.Work || d.Bundle.Scope.Global != w.Generation || d.Bundle.Scope.Generation != w.Generation || d.Bundle.ClosingEscrow != nil || d.Bundle.PlanIntent == nil {
		return ErrRecovery
	}
	if d.Phase == "scope_retired" {
		if d.Retirement == nil || !freshScopeMatchesV3(d.Retirement, w.Snapshot.Identity, d.Retirement.New, d.Work) {
			return ErrRecovery
		}
	} else if d.Retirement != nil {
		return ErrRecovery
	}
	in := d.Bundle.PlanIntent
	if in.DHCPWork != d.Work || in.Kind != v3RoutedDHCPKind || !validGuardDeadlineShapeV2(in) || in.Previous != w.Configuration || in.Target != w.Configuration || in.TargetGeneration != w.Generation || in.Operation != reserveWorkV2(d.Bundle) || !d.Bundle.Scope.Deadline.IsZero() || d.Bundle.Scope.Lease != "" {
		return ErrRecovery
	}
	var audit v2CoordinatorAudit
	if load(d.Audit, &audit) != nil || audit.Format != v2Format || audit.Operation != in.Operation || audit.Kind != v3RoutedDHCPKind || audit.Result != d.Phase || audit.Generation != w.Generation || audit.Running != w.Running || audit.Sequence == 0 {
		return ErrRecovery
	}
	return nil
}

func validateRoutedDHCPArchiveV3(archive v2ReserveArchive, facts v2ReserveFinality, state v2State, load func(string, any) error) error {
	if !hasFeatureV2(state, v3RoutedDHCPFeature) || facts.Version != 1 || facts.Child != nil || facts.Recovery != nil || facts.Resolution != "" || archive.Child != "" || archive.LeaseResolution != "" || len(archive.UnusedEscrow) != 0 {
		return ErrRecovery
	}
	var d v3RoutedDHCPState
	if load(facts.Origin.Object, &d) != nil || validateRoutedDHCPTerminalV3(d, state.Lineage, load) != nil || reserveWorkV2(d.Bundle) != facts.Origin.ID || d.Audit != archive.Audit || !archiveMatchesBundleV2(archive, d.Bundle, false) {
		return ErrRecovery
	}
	if d.Phase == "scope_retired" && !hasFeatureV2(state, v3RoutedFreshScopeFeature) {
		return ErrRecovery
	}
	return nil
}

func (s *v2Store) verifyRoutedDHCPLastV3() error {
	if s.state.RoutedDHCPLast == "" {
		return nil
	}
	var d v3RoutedDHCPState
	if s.readObject(s.state.RoutedDHCPLast, &d) != nil || validateRoutedDHCPTerminalV3(d, s.state.Lineage, s.readObject) != nil {
		return ErrRecovery
	}
	entry := v2ReserveArchiveEntry{Claim: d.Bundle.Claims.Admission, Binding: &d.Bundle.Admission, Scope: &d.Bundle.Scope}
	archive, known, err := s.reserveArchiveBundleLookupV2(s.state.ReserveArchiveRoot, entry, "binding")
	if err != nil || !known || validateArchiveFinalityV2(archive, s.state, s.readObject) != nil {
		return ErrRecovery
	}
	var facts v2ReserveFinality
	if s.readObject(archive.FinalWork, &facts) != nil || facts.Origin.Object != s.state.RoutedDHCPLast {
		return ErrRecovery
	}
	return nil
}

func (w *RoutedDHCPSelectedStoreV3) freshGrant(g RoutedDHCPGrantV3) error {
	s := w.c.store
	if err := s.verifyRoutedDHCPLastV3(); err != nil {
		return err
	}
	if s.state.RoutedDHCPLast == "" {
		return nil
	}
	var d v3RoutedDHCPState
	if s.readObject(s.state.RoutedDHCPLast, &d) != nil {
		return ErrRecovery
	}
	previous, err := loadRoutedDHCPWorkV3(d.Work, s.state.Lineage, s.readObject)
	if err != nil {
		return err
	}
	if previous.Snapshot.Fact().Owner == g.Snapshot.Fact().Owner && (g.Epoch <= previous.Epoch || g.Snapshot.Sequence <= previous.Snapshot.Sequence) {
		return ErrRecovery
	}
	return nil
}

// The fixed reserve leaves room for selection/audit/finality and one retry,
// plus the actual archive trie insertion. Refuse before taking physical slots.
func (w *RoutedDHCPSelectedStoreV3) profile(owner string) error {
	s := w.c.store
	key, err := reserveBundleKeyV2(s.state.Lineage, owner)
	if err != nil {
		return err
	}
	cost, err := reserveIndexCostV2(s, s.state.ReserveArchiveRoot, key, "archive", false)
	if err != nil || cost+32 > v2OperationReserveInodes {
		return errV2Limited
	}
	if err = s.physicalCapacity(v2OperationReserveBytes, v2OperationReserveInodes); err != nil {
		return err
	}
	// All roles must still be fixed System-capable profiles, not caller-selected
	// arbitrary slots. No new pool format is introduced.
	for _, role := range []recoveryreserve.RoleV2{recoveryreserve.AdmissionV2, recoveryreserve.PlanV2, recoveryreserve.EmergencyV2} {
		if _, err := s.reserves.pool(role).Profile(); err != nil {
			return ErrRecovery
		}
	}
	return nil
}

package configpoc

// A fresh boot after selected scope retirement differs from its attach anchor
// by exactly one audited DHCP terminal. It does not authorize ordinary apply,
// adopt old L3, or substitute a matching Running hash for G1/R2 provenance.
func coldDHCPScopeRetirementV3(v *selectedViewV2, a RoutedColdAnchorV1, anchored v2State, p RoutedSelectedPlanV1, purpose RoutedSelectionPurposeV2) bool {
	if p.work.Kind != v2BootKind || !p.Cold() || p.work.Boundary != nil || p.work.FreshScope == nil || p.bootRecord == nil || !routedBootRecordMatchesV2(p, *p.bootRecord) || anchored.RoutedDHCP == nil || routedDHCPTerminalV3(anchored.RoutedDHCP) || anchored.RoutedActive == nil || a.configuration.Intent != nil || a.configuration.Pending != nil || a.configuration.RecoveryRequired || v.store.state.RoutedDHCP != nil || v.store.state.RoutedDHCPLast == "" {
		return false
	}
	switch purpose {
	case SelectionBootstrapV2, SelectionConfirmV2, SelectionResumeV2, SelectionMatchBeforeV2, SelectionMatchTargetV2:
	default:
		return false
	}
	var terminal v3RoutedDHCPState
	if v.store.readObject(v.store.state.RoutedDHCPLast, &terminal) != nil || terminal.Phase != "scope_retired" || validateRoutedDHCPTerminalV3(terminal, v.ref.Lineage, v.store.readObject) != nil || terminal.Work != anchored.RoutedDHCP.Work || !reserveJSONEqualV2(terminal.Bundle, anchored.RoutedDHCP.Bundle) || terminal.Retirement == nil {
		return false
	}
	x, y := terminal.Retirement, p.work.FreshScope
	if !ValidRoutedFreshScopeEvidenceV3(*y) || y.Work != anchored.RoutedActive.Work || x.Old != y.Old || x.New != y.New || x.ReceiptSHA256 != y.ReceiptSHA256 || x.MetadataSHA256 != y.MetadataSHA256 || x.DrainedAtBootNS != y.DrainedAtBootNS || x.Before != y.Before || x.Dependencies != y.Dependencies || x.ObservedAtBootNS > y.ObservedAtBootNS {
		return false
	}
	var previous v2Configuration
	var audit v2CoordinatorAudit
	if v.store.readObject(p.work.Transition.Previous, &previous) != nil || v.store.readObject(terminal.Audit, &audit) != nil || audit.Operation != reserveWorkV2(terminal.Bundle) || audit.Kind != v3RoutedDHCPKind || audit.Result != "scope_retired" || audit.Subject != "" || audit.OriginCommit != "" || audit.Lease != "" || audit.Generation != a.reference.Generation || !coldCompletionAuditV1(a.configuration, previous, audit) {
		return false
	}
	expected := clone(a.configuration)
	expected.AuditTip, expected.AuditSequence = terminal.Audit, audit.Sequence
	return coldSameConfigurationV1(expected, previous)
}

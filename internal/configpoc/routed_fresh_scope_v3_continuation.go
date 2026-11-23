package configpoc

// A fresh boot after selected scope retirement differs from its attach anchor
// by exactly one audited DHCP terminal. It does not authorize ordinary apply,
// adopt old L3, or substitute a matching Running hash for G1/R2 provenance.
func coldDHCPScopeRetirementV3(v *selectedViewV2, a RoutedColdAnchorV1, anchored v2State, p RoutedSelectedPlanV1, purpose RoutedSelectionPurposeV2) bool {
	if p.work.Kind != v2BootKind || !p.Cold() || p.work.Boundary != nil || p.work.FreshScope == nil && p.work.RebootScope == nil || p.bootRecord == nil || !routedBootRecordMatchesV2(p, *p.bootRecord) || anchored.RoutedDHCP == nil || routedDHCPTerminalV3(anchored.RoutedDHCP) || anchored.RoutedActive == nil || a.configuration.Intent != nil || a.configuration.Pending != nil || a.configuration.RecoveryRequired || v.store.state.RoutedDHCP != nil || v.store.state.RoutedDHCPLast == "" {
		return false
	}
	switch purpose {
	case SelectionBootstrapV2, SelectionConfirmV2, SelectionResumeV2, SelectionMatchBeforeV2, SelectionMatchTargetV2:
	default:
		return false
	}
	var terminal v3RoutedDHCPState
	if v.store.readObject(v.store.state.RoutedDHCPLast, &terminal) != nil || terminal.Phase != "scope_retired" || validateRoutedDHCPTerminalV3(terminal, v.ref.Lineage, v.store.readObject) != nil || terminal.Work != anchored.RoutedDHCP.Work || !reserveJSONEqualV2(terminal.Bundle, anchored.RoutedDHCP.Bundle) {
		return false
	}
	x, validX := compareScopeV4(terminal.Retirement, terminal.RebootRetirement)
	y, validY := compareScopeV4(p.work.FreshScope, p.work.RebootScope)
	if !validX || !validY || y.work != anchored.RoutedActive.Work || x.old != y.old || x.next != y.next || x.receipt != y.receipt || x.metadata != y.metadata || x.drained != y.drained || x.before != y.before || x.dependencies != y.dependencies || x.reboot != y.reboot || x.attested != y.attested || x.observed > y.observed {
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

func coldRetainedDHCPRecoveryV1(v *selectedViewV2, a RoutedColdAnchorV1, anchored v2State, p RoutedSelectedPlanV1, purpose RoutedSelectionPurposeV2) bool {
	if p.work.Kind != v2BootKind || !p.Cold() || p.work.Boundary != nil || p.work.RebootScope == nil ||
		p.bootRecord == nil || !routedBootRecordMatchesV2(p, *p.bootRecord) || a.configuration.RecoveryRequired ||
		v.store.state.RoutedDHCP != nil || !hasFeatureV2(v.store.state, retainedDHCPColdRetirementFeatureV1) {
		return false
	}
	switch purpose {
	case SelectionBootstrapV2, SelectionConfirmV2, SelectionResumeV2, SelectionMatchBeforeV2, SelectionMatchTargetV2:
	default:
		return false
	}
	var retired v3RoutedDHCPState
	load := v.store.readObject
	if load(v.store.state.RoutedDHCPLast, &retired) != nil || retired.ColdSource == "" ||
		validateRoutedDHCPTerminalV3(retired, v.ref.Lineage, load) != nil {
		return false
	}
	// A helper can attach before the cold detach, after it, or after archiving
	// the Work. Each anchor still names the same original reserve and proof.
	if d := anchored.RoutedDHCP; d != nil {
		if d.Work != retired.Work || !reserveJSONEqualV2(retired.Bundle, d.Bundle) {
			return false
		}
		if d.ColdSource == "" {
			if a.reference.Selection != retired.ColdSource {
				return false
			}
		} else if d.ColdSource != retired.ColdSource || d.RebootRetirement == nil || *d.RebootRetirement != *retired.RebootRetirement ||
			d.ColdAuditSource != "" && (d.ColdAuditSource != retired.ColdAuditSource || d.Audit != retired.Audit) {
			return false
		}
	} else if anchored.RoutedDHCPLast != v.store.state.RoutedDHCPLast {
		return false
	}
	source, err := readRetainedDHCPColdSelectionV1(retired.ColdAuditSource, v.ref.Lineage, load)
	prior, next := retired.RebootRetirement, p.work.RebootScope
	if err != nil || source.RoutedActive == nil || source.RoutedActive.Work != next.Work || prior.Old != next.Old || prior.MetadataSHA256 != next.MetadataSHA256 {
		return false
	}
	if prior.New.BootID == next.New.BootID &&
		(prior.New != next.New || prior.ReceiptSHA256 != next.ReceiptSHA256 || prior.Before != next.Before ||
			prior.Dependencies != next.Dependencies || prior.ObservedAtNewBootNS > next.ObservedAtNewBootNS) {
		return false
	}
	var before v2Configuration
	var audit v2CoordinatorAudit
	if load(p.work.Transition.Previous, &before) != nil || load(retired.Audit, &audit) != nil {
		return false
	}
	expected := clone(*source.Configuration)
	expected.AuditTip, expected.AuditSequence = retired.Audit, audit.Sequence
	if !coldSameConfigurationV1(before, expected) {
		return false
	}
	if a.configuration.Intent == nil && a.configuration.Pending == nil {
		return coldSameConfigurationV1(a.configuration, *source.Configuration) || coldSameConfigurationV1(a.configuration, expected)
	}
	return coldCompletedConfigurationV1(v, a, *source.Configuration)
}

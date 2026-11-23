package configpoc

import (
	"context"
	"fmt"
	"reflect"
)

const retainedDHCPColdRetirementFeatureV1 = "configuration.routed-dhcp-cold-retirement.v1"

func retainedDHCPInterruptedV1(s v2State) bool {
	cfg := s.Configuration
	return cfg != nil && !cfg.RecoveryRequired && (cfg.Intent != nil || cfg.Pending != nil) &&
		s.RoutedDHCPConfiguration != nil && s.RoutedBootBoundary == nil &&
		s.RoutedDHCP != nil && s.RoutedDHCP.Phase == "applied"
}

func readRetainedDHCPColdSelectionV1(hash, lineage string, load func(string, any) error) (v2State, error) {
	var selection v2Selection
	var state v2State
	if !validHash(hash) || load(hash, &selection) != nil || !v2ValidSelection(selection) ||
		selection.Lineage != lineage || load(selection.State, &state) != nil ||
		state.Lineage != lineage || state.Configuration == nil || !validV2Configuration(state.Configuration) {
		return v2State{}, ErrRecovery
	}
	return state, nil
}

func retainedDHCPColdSourceV1(d v3RoutedDHCPState, lineage string, load func(string, any) error) (v2State, error) {
	source, err := readRetainedDHCPColdSelectionV1(d.ColdSource, lineage, load)
	if err != nil || d.Phase != "scope_retired" || d.RebootRetirement == nil || d.Retirement != nil ||
		!retainedDHCPInterruptedV1(source) || source.RoutedDHCP.Work != d.Work || !reserveJSONEqualV2(source.RoutedDHCP.Bundle, d.Bundle) {
		return v2State{}, ErrRecovery
	}
	work, err := loadRoutedDHCPWorkV3(d.Work, lineage, load)
	proof := d.RebootRetirement
	if err != nil || !rebootScopeMatchesV4(proof, work.Snapshot.Identity, proof.New, d.Work) {
		return v2State{}, ErrRecovery
	}
	return source, nil
}

func retainedDHCPColdAuditFollowsV1(before, after *v3RoutedDHCPState) bool {
	if before == nil || after == nil || before.ColdSource == "" || before.ColdAuditSource != "" || before.Audit != "" || after.ColdAuditSource == "" {
		return false
	}
	expected := *after
	expected.ColdAuditSource, expected.Audit = "", ""
	return reflect.DeepEqual(*before, expected)
}

func validateRetainedDHCPColdAuditV1(d v3RoutedDHCPState, lineage string, audit v2CoordinatorAudit, load func(string, any) error) error {
	if _, err := retainedDHCPColdSourceV1(d, lineage, load); err != nil {
		return err
	}
	source, err := readRetainedDHCPColdSelectionV1(d.ColdAuditSource, lineage, load)
	if err != nil || source.Configuration.Intent != nil || source.Configuration.Pending != nil || source.Configuration.RecoveryRequired ||
		source.RoutedDHCPConfiguration != nil || !retainedDHCPColdAuditFollowsV1(source.RoutedDHCP, &d) ||
		audit.Generation != source.Generation || audit.OriginCommit != "" || audit.Subject != "" || audit.Lease != "" ||
		!coldCompletionAuditV1(*source.Configuration, *source.Configuration, audit) {
		return ErrRecovery
	}
	return nil
}

func validatesRetainedDHCPColdEdgeV1(previous, next v2State, source SelectionReferenceV2, load func(string, any) error) bool {
	d := next.RoutedDHCP
	if !retainedDHCPInterruptedV1(previous) || d == nil || d.ColdSource != source.Selection ||
		source.WorkHash != d.Work || d.ColdAuditSource != "" || d.Audit != "" ||
		!hasFeatureV2(next, retainedDHCPColdRetirementFeatureV1) {
		return false
	}
	if _, err := retainedDHCPColdSourceV1(*d, next.Lineage, load); err != nil {
		return false
	}
	expected := clone(previous)
	expected.RoutedDHCPConfiguration = nil
	expected.RoutedDHCP = clone(d)
	addFeatureV2(&expected, retainedDHCPColdRetirementFeatureV1)
	addRebootScopeFeaturesV4(&expected, d.RebootRetirement)
	return reflect.DeepEqual(expected, next)
}

func validatesRetainedDHCPColdAuditEdgeV1(previous, next v2State, source string, load func(string, any) error) bool {
	d := next.RoutedDHCP
	if !retainedDHCPColdAuditFollowsV1(previous.RoutedDHCP, d) || d.ColdAuditSource != source ||
		!hasFeatureV2(next, retainedDHCPColdRetirementFeatureV1) ||
		validateRoutedDHCPTerminalV3(*d, next.Lineage, load) != nil {
		return false
	}
	var audit v2CoordinatorAudit
	if load(d.Audit, &audit) != nil {
		return false
	}
	expected := clone(previous)
	expected.RoutedDHCP = clone(d)
	expected.Configuration.AuditTip, expected.Configuration.AuditSequence = d.Audit, audit.Sequence
	return reflect.DeepEqual(expected, next)
}

func (c *v2Coordinator) retireRetainedDHCPOnColdBootV1(ctx context.Context, work v3RoutedDHCPWork) error {
	s := c.store
	d := s.state.RoutedDHCP
	if !retainedDHCPInterruptedV1(s.state) || c.options.BootID == nil ||
		string(*c.options.BootID) != c.options.RoutedIdentity.BootID || s.reserves == nil ||
		s.reserves.verifySelected(s) != nil ||
		validateRoutedDHCPConfigurationSelectionV4(s.state.RoutedDHCPConfiguration, s.state, s.readObject, s.lookupRetained, routedDHCPConfigurationHeaderV4) != nil {
		return ErrRecovery
	}
	proof, err := c.proveRebootScopeV4(ctx, work.Snapshot.Identity, d.Work)
	if err != nil {
		return err
	}
	cfg := s.state.Configuration
	var configurationWork string
	if cfg.Intent != nil {
		configurationWork = cfg.Intent.RoutedWork
	} else {
		origin, e := s.lookupRetained(cfg.Pending.Owner, cfg.Pending.OriginCommit)
		if e != nil || !pendingOriginMatchesV2(cfg.Pending, origin) || origin.Reserve == nil || origin.Reserve.PlanIntent == nil {
			return ErrRecovery
		}
		configurationWork = origin.Reserve.PlanIntent.RoutedWork
	}
	plan, err := loadRoutedWorkV2(configurationWork, s.state.Lineage, s.readObject)
	if err != nil || plan.work.Boundary != nil || plan.Scope().Identity != work.Snapshot.Identity {
		return ErrRecovery
	}
	if _, err = c.proveRebootScopeV4(ctx, plan.Scope().Identity, configurationWork); err != nil {
		return err
	}
	if err = c.point("before_cold_dhcp_retirement"); err != nil {
		return err
	}
	previousAllowance := s.allowance
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = previousAllowance }()
	st := clone(s.state)
	st.RoutedDHCP.Phase = "scope_retired"
	st.RoutedDHCP.ColdSource = s.selector.Current
	st.RoutedDHCPConfiguration = nil
	again, err := c.proveRebootScopeV4(ctx, work.Snapshot.Identity, d.Work)
	if err != nil {
		return err
	}
	check := *again
	check.ObservedAtNewBootNS = proof.ObservedAtNewBootNS
	if check != *proof || again.ObservedAtNewBootNS < proof.ObservedAtNewBootNS {
		return ErrRecovery
	}
	st.RoutedDHCP.RebootRetirement = again
	addFeatureV2(&st, retainedDHCPColdRetirementFeatureV1)
	addRebootScopeFeaturesV4(&st, proof)
	if err = s.publish(st); err != nil {
		return err
	}
	// Keep the Commit's audit adjacent to its plan. The Work no longer conveys
	// any authority, and its final audit and physical archive wait for the Commit.
	return c.point("after_cold_dhcp_retirement")
}

func (c *v2Coordinator) finishRetainedDHCPColdRecoveryV1(ctx context.Context) error {
	s := c.store
	if d := s.state.RoutedDHCP; d == nil || d.ColdSource == "" {
		return nil
	}
	if cfg := s.state.Configuration; cfg.Intent != nil {
		if err := c.archiveInterruptedRoutedV4(ctx); err != nil {
			return fmt.Errorf("archive selected intent: %w", err)
		}
		if s.state.Configuration.Intent != nil {
			return ErrRecovery
		}
	}
	if pending := s.state.Configuration.Pending; pending != nil {
		if pending.Domain != "routed" {
			return ErrRecovery
		}
		origin, err := s.lookupRetained(pending.Owner, pending.OriginCommit)
		if err != nil || !pendingOriginMatchesV2(pending, origin) || origin.Reserve == nil || origin.Reserve.PlanIntent == nil {
			return ErrRecovery
		}
		work := origin.Reserve.PlanIntent.RoutedWork
		plan, err := loadRoutedWorkV2(work, s.state.Lineage, s.readObject)
		if err != nil || plan.work.Boundary != nil {
			return ErrRecovery
		}
		if _, err = c.proveRebootScopeV4(ctx, plan.Scope().Identity, work); err != nil {
			return err
		}
		// Use the Commit's already reserved capacity without running a rollback.
		if err = c.startRecoveryLocked("restart"); err != nil {
			return err
		}
		if err = c.archiveInterruptedRoutedV4(ctx); err != nil {
			return err
		}
	}
	if cfg := s.state.Configuration; cfg.Intent != nil || cfg.Pending != nil || cfg.RecoveryRequired {
		return ErrRecovery
	}
	if d := s.state.RoutedDHCP; d != nil && d.ColdAuditSource == "" {
		if err := c.auditRetainedDHCPColdRetirementV1(); err != nil {
			return err
		}
	}
	return s.reserves.maintain(s)
}

func (c *v2Coordinator) auditRetainedDHCPColdRetirementV1() error {
	s := c.store
	previousAllowance := s.allowance
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = previousAllowance }()
	st := clone(s.state)
	d := st.RoutedDHCP
	audit, err := c.appendAuditLocked(st.Configuration, reserveWorkV2(d.Bundle), "", "", "", v3RoutedDHCPKind, "scope_retired", st.Generation, c.now())
	if err != nil {
		return err
	}
	d.ColdAuditSource, d.Audit = s.selector.Current, audit
	if err = c.point("before_cold_dhcp_audit"); err != nil {
		return err
	}
	if err = s.publish(st); err != nil {
		return err
	}
	return c.point("after_cold_dhcp_audit")
}

package configpoc

import "reflect"

func retainedDHCPClosingIntentV4(c routedDHCPConfigurationContextV4, in *v2CoordinatorIntent, load func(string, any) error) bool {
	pending := c.target.Pending
	if c.closing != nil || c.transition.Group == nil || !pendingOriginMatchesV2(pending, c.operation) || in == nil ||
		in.Domain != "routed" || in.Subject != pending.Owner || in.RoutedWork != c.transition.Group.Work ||
		in.Previous != c.finalConfiguration || c.transition.Generation == ^uint64(0) ||
		in.TargetGeneration != c.transition.Generation+1 || in.BootID != nil || in.GuardDeadline != nil {
		return false
	}
	if in.Recovery {
		if in.Kind != "timeout" && in.Kind != "restart" || in.OriginCommit != pending.OriginCommit || in.Lease != pending.Lease {
			return false
		}
	} else if in.Kind != OpConfirm || in.OriginCommit != "" || in.Lease != "" {
		return false
	}
	plan, err := loadRoutedWorkV2(in.RoutedWork, c.transition.Lineage, load)
	return err == nil && validateRoutedWorkIntentV2(in, plan, load) == nil
}

func retainedDHCPClosingPendingV4(c routedDHCPConfigurationContextV4, cfg v2Configuration, load func(string, any) error) bool {
	in := cfg.Intent
	if !retainedDHCPClosingIntentV4(c, in, load) {
		return false
	}
	cfg.Intent = nil
	if in.Recovery {
		var record v2RecoveryRecord
		if load(cfg.LastRecovery, &record) != nil || record.State != "pending" || record.ID != in.Operation ||
			record.Kind != in.Kind || record.Origin != in.OriginCommit || record.Lease != in.Lease ||
			record.Previous != in.Previous || record.Target != in.Target || record.Subject != in.Subject ||
			!validRecoveryRecordV2(record, c.transition.Lineage) || !reflect.DeepEqual(record.Reserve, c.operation.Reserve) {
			return false
		}
		cfg.LastRecovery, cfg.RecoveryIndex = c.target.LastRecovery, c.target.RecoveryIndex
	}
	return reflect.DeepEqual(cfg, c.target)
}

func readRetainedDHCPClosingV4(c *routedDHCPConfigurationContextV4, close *v4RoutedDHCPClosing, st v2State, load func(string, any) error) error {
	in := &close.Intent
	if !validHash(close.Result) || !validHash(close.Final) || !retainedDHCPClosingIntentV4(*c, in, load) || st.Generation < in.TargetGeneration {
		return ErrRecovery
	}
	var projected, final v2Configuration
	if load(in.Target, &projected) != nil || load(close.Final, &final) != nil || !validV2Configuration(&final) {
		return ErrRecovery
	}
	var auditHash string
	var auditAtComparison func(v2CoordinatorAudit) bool
	if in.Recovery {
		var record v2RecoveryRecord
		if close.Result != final.LastRecovery || load(close.Result, &record) != nil ||
			!validRecoveryRecordV2(record, c.transition.Lineage) || record.State != "final" || record.ID != in.Operation ||
			record.Kind != in.Kind || record.Origin != in.OriginCommit || record.Lease != in.Lease ||
			record.Previous != in.Previous || record.Target != in.Target || record.Subject != in.Subject ||
			record.Started.Before(c.target.Pending.Deadline) || !reflect.DeepEqual(record.Reserve, c.operation.Reserve) {
			return ErrRecovery
		}
		projected.LastRecovery, projected.RecoveryIndex = final.LastRecovery, final.RecoveryIndex
		auditHash = record.Audit
		auditAtComparison = func(a v2CoordinatorAudit) bool {
			return a.Subject == "system" && a.Result == "reverted" && !a.At.Before(record.Started)
		}
	} else {
		var op v2Operation
		pending := c.target.Pending
		if load(close.Result, &op) != nil || op.State != "final" || op.ID != in.Operation ||
			op.Subject != in.Subject || op.Lineage != c.transition.Lineage || op.Domain != "routed" || op.Request.Kind != OpConfirm ||
			!v2RequestValid(op.Domain, op.Request) || op.Fingerprint != v2OperationFingerprint(op) ||
			op.Request.Origin != pending.OriginCommit || op.Request.Target != pending.Target ||
			op.Expected != c.transition.Generation || op.Completed == nil || !op.Completed.Before(pending.Deadline) ||
			op.Outcome == nil || op.Outcome.Code != "applied" || op.Outcome.Generation != in.TargetGeneration ||
			op.Outcome.RunningRevision != final.Running.Hash || op.Outcome.StartupRevision != final.Startup.Hash ||
			op.Outcome.ConfirmationDeadline != nil || op.Outcome.ConfirmationLease != "" || op.ClosingCredit == "" ||
			op.Reserve == nil || op.Reserve.PlanIntent == nil || !reflect.DeepEqual(*op.Reserve.PlanIntent, *in) ||
			!reserveScopeMatchesOperationV2(op.Reserve, op) {
			return ErrRecovery
		}
		auditHash = op.Outcome.AuditHash
		auditAtComparison = func(a v2CoordinatorAudit) bool {
			return a.Subject == op.Subject && a.Result == "applied" && a.At.Equal(*op.Completed)
		}
	}
	var audit v2CoordinatorAudit
	if !sameDHCPConfigurationV4(projected, final) ||
		auditHash != final.AuditTip || load(auditHash, &audit) != nil ||
		audit.Operation != in.Operation || audit.Kind != in.Kind || audit.OriginCommit != c.target.Pending.OriginCommit ||
		audit.Lease != c.target.Pending.Lease || audit.Generation != in.TargetGeneration || audit.Running != final.Running.Hash ||
		audit.Startup != final.Startup.Hash || audit.Sequence != final.AuditSequence || audit.Previous != c.target.AuditTip ||
		c.target.AuditSequence == ^uint64(0) || audit.Sequence != c.target.AuditSequence+1 || !auditAtComparison(audit) {
		return ErrRecovery
	}
	c.closing = close
	c.finalConfiguration = close.Final
	c.target = final
	return nil
}

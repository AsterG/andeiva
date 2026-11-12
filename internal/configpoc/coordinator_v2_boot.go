package configpoc

import (
	"context"
	"regexp"
	"time"
)

const v2BootKind = "boot_startup"
const v2BootFeature = "boot_startup.v1"

// A boot identity comes from trusted assembly, never an operation request.
type v2BootID string

var v2BootPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func validBootIDV2(id v2BootID) bool {
	return v2BootPattern.MatchString(string(id)) && id != "00000000-0000-0000-0000-000000000000"
}

func validBootIntentV2(intent *v2CoordinatorIntent) bool {
	return intent != nil && intent.Kind == v2BootKind && intent.Recovery && intent.BootID != nil && validBootIDV2(*intent.BootID) && intent.Subject == "" && intent.OriginCommit == "" && intent.Lease == ""
}

func validFeaturesV2(state v2State) bool {
	if len(state.RequiredFeatures) > 1 || (len(state.RequiredFeatures) == 1 && state.RequiredFeatures[0] != v2BootFeature) {
		return false
	}
	if state.Configuration != nil && (state.Configuration.LastCompletedBoot != "" || (state.Configuration.Intent != nil && state.Configuration.Intent.Kind == v2BootKind)) {
		return len(state.RequiredFeatures) == 1
	}
	return true
}

func preservesFeaturesV2(previous, next v2State) bool {
	return len(previous.RequiredFeatures) == 0 || (len(next.RequiredFeatures) == 1 && next.RequiredFeatures[0] == v2BootFeature)
}

// This optional adapter is only assembled with the existing authenticated,
// one-time bootstrap verb. Normal Engine.Apply still requires a lease.
type startupBootstrapV2 interface {
	BootstrapStartup(context.Context, string, Revision) error
	ConfirmStartup(context.Context, string, Revision, Revision) error
}

func (c *v2Coordinator) bootStartupLocked(ctx context.Context, id v2BootID) error {
	s := c.store
	current := clone(*s.state.Configuration)
	if current.LastCompletedBoot != "" {
		var completed v2RecoveryRecord
		if s.readObject(current.LastCompletedBoot, &completed) != nil || !validRecoveryRecordV2(completed, s.state.Lineage) || completed.Kind != v2BootKind || completed.State != "final" {
			return ErrRecovery
		}
		if *completed.BootID == id {
			if !c.readback(current) {
				return ErrRecovery
			}
			return nil
		}
	}
	if current.Intent != nil || current.Pending != nil || current.Candidate != nil || current.RecoveryRequired || current.LocalServices.Running.Hash != current.LocalServices.Startup.Hash || !c.localReadback(current) {
		return ErrRecovery
	}
	if s.state.Generation == ^uint64(0) || current.Firewall.Generation == ^uint64(0) || s.used.Bytes+s.state.ReservedBytes+2*v2OperationReserveBytes > s.budget.Bytes || s.used.Inodes+s.state.ReservedInodes+2*v2OperationReserveInodes > s.budget.Inodes {
		return errV2Limited
	}
	target := clone(current)
	target.Firewall.Running = target.Firewall.Startup
	target.Firewall.LastGood = target.Firewall.Startup
	target.Firewall.Generation++
	if target.refresh() != nil {
		return ErrInvalid
	}
	for _, engine := range c.firewall {
		if engine.Validate(target.Firewall.Running.Config) != nil {
			return ErrEngine
		}
	}
	previousHash, err := s.object(current)
	if err != nil {
		return err
	}
	targetHash, err := s.object(target)
	if err != nil {
		return err
	}
	issued, err := v2ID("boot", s.selection.Sequence+1)
	if err != nil {
		return err
	}
	record := v2RecoveryRecord{Format: v2Format, ID: issued, BootID: &id, Kind: v2BootKind, State: "pending", Previous: previousHash, Target: targetHash, Lineage: s.state.Lineage, Started: c.recoveryNow(), Pinned: true}
	hash, err := s.object(record)
	if err != nil {
		return err
	}
	st := clone(s.state)
	st.RequiredFeatures = []string{v2BootFeature}
	st.Configuration.LastRecovery = hash
	st.Configuration.RecoveryIndex, err = c.recoveryIndexPut(st.Configuration.RecoveryIndex, record, hash)
	if err != nil {
		return err
	}
	st.Configuration.Intent = &v2CoordinatorIntent{Operation: issued, Domain: "firewall", Kind: v2BootKind, Previous: previousHash, Target: targetHash, TargetGeneration: st.Generation + 1, Recovery: true, BootID: &id}
	st.ReservedBytes += v2OperationReserveBytes
	st.ReservedInodes += v2OperationReserveInodes
	st.Clock = c.recoveryNow()
	if err := c.point("before_boot_intent"); err != nil {
		return err
	}
	if err := s.publish(st); err != nil {
		return err
	}
	if err := c.point("after_boot_intent"); err != nil {
		return err
	}
	return c.finishBootLocked(ctx)
}

func (c *v2Coordinator) finishBootLocked(ctx context.Context) error {
	s := c.store
	intent := s.state.Configuration.Intent
	if !validBootIntentV2(intent) || c.options.BootID == nil || *intent.BootID != *c.options.BootID || s.state.ReservedBytes < v2OperationReserveBytes || s.state.ReservedInodes < v2OperationReserveInodes {
		return ErrRecovery
	}
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = v2Budget{} }()
	var previous, target v2Configuration
	var record v2RecoveryRecord
	if s.readObject(intent.Previous, &previous) != nil || s.readObject(intent.Target, &target) != nil || !validV2Configuration(&previous) || !validV2Configuration(&target) || previous.Intent != nil || previous.Pending != nil || target.Intent != nil || target.Pending != nil || target.Candidate != nil || target.Firewall.Running.Hash != previous.Firewall.Startup.Hash || target.Firewall.Startup.Hash != previous.Firewall.Startup.Hash || target.LocalServices.Running.Hash != previous.LocalServices.Running.Hash || target.LocalServices.Startup.Hash != previous.LocalServices.Startup.Hash || target.Firewall.Generation != previous.Firewall.Generation+1 || target.LocalServices.Generation != previous.LocalServices.Generation || s.readObject(s.state.Configuration.LastRecovery, &record) != nil || !validRecoveryRecordV2(record, s.state.Lineage) || record.ID != intent.Operation || record.Kind != v2BootKind || record.State != "pending" || *record.BootID != *intent.BootID || record.Previous != intent.Previous || record.Target != intent.Target || intent.TargetGeneration != s.state.Generation+1 {
		return ErrRecovery
	}
	if !c.localReadback(target) {
		return ErrRecovery
	}
	for _, engine := range c.firewall {
		if engine.Validate(target.Firewall.Running.Config) != nil {
			return ErrEngine
		}
	}
	for _, engine := range c.firewall {
		if engine.Current() == target.Firewall.Running.Hash {
			continue
		}
		if engine.Current() == previous.Firewall.Running.Hash {
			if guard, ok := engine.(ActivationGuard); ok {
				if guard.Arm(ctx, record.ID, previous.Firewall.Running, target.Firewall.Running, 10*time.Second) != nil {
					return ErrRecovery
				}
				if engine.Apply(ctx, target.Firewall.Running) != nil || engine.Current() != target.Firewall.Running.Hash {
					return ErrRecovery
				}
			} else if engine.Apply(ctx, target.Firewall.Running) != nil {
				return ErrEngine
			}
		} else if bootstrap, ok := engine.(startupBootstrapV2); ok {
			if bootstrap.BootstrapStartup(ctx, record.ID, target.Firewall.Running) != nil {
				return ErrRecovery
			}
		} else {
			return ErrRecovery
		}
		if err := c.point("after_boot_engine"); err != nil {
			return err
		}
	}
	if !c.readback(target) {
		return ErrRecovery
	}
	for _, engine := range c.firewall {
		if bootstrap, ok := engine.(startupBootstrapV2); ok {
			if bootstrap.ConfirmStartup(ctx, record.ID, previous.Firewall.Running, target.Firewall.Running) != nil {
				return ErrRecovery
			}
		} else if guard, ok := engine.(ActivationGuard); ok {
			if guard.Arm(ctx, record.ID, previous.Firewall.Running, target.Firewall.Running, 10*time.Second) != nil || guard.Confirm(ctx, record.ID, target.Firewall.Running.Hash) != nil {
				return ErrRecovery
			}
		}
	}
	if !c.readback(target) {
		return ErrRecovery
	}
	if err := c.point("after_boot_readback"); err != nil {
		return err
	}
	audit, err := c.appendAuditLocked(&target, record.ID, "", "", "system", v2BootKind, "verified", intent.TargetGeneration, c.recoveryNow())
	if err != nil {
		return err
	}
	target.VerifiedIndex, err = c.verifiedInsert(target.VerifiedIndex, 0, v2VerifiedEntry{Revision: target.Running.Hash, Audit: audit, Operation: record.ID})
	if err != nil {
		return err
	}
	completed := c.recoveryNow()
	until := completed.Add(30 * 24 * time.Hour)
	record.State, record.Audit, record.Pinned = "final", audit, false
	record.Completed, record.RetainUntil = &completed, &until
	hash, err := s.object(record)
	if err != nil {
		return err
	}
	target.LastRecovery, target.LastCompletedBoot = hash, hash
	target.RecoveryIndex, err = c.recoveryIndexPut(s.state.Configuration.RecoveryIndex, record, hash)
	if err != nil {
		return err
	}
	st := clone(s.state)
	st.Configuration = &target
	st.Generation = intent.TargetGeneration
	st.ReservedBytes -= v2OperationReserveBytes
	st.ReservedInodes -= v2OperationReserveInodes
	st.Clock = completed
	if err := c.point("before_boot_completion"); err != nil {
		return err
	}
	if err := s.publish(st); err != nil {
		return err
	}
	return c.point("after_boot_completion")
}

package configpoc

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"time"
)

const v2BootKind = "boot_startup"
const v2BootFeature = "boot_startup.v1"
const v2LocalFeature = "local_services_transactions.v1"

// A boot identity comes from trusted assembly, never an operation request.
type v2BootID string

var v2BootPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func validBootIDV2(id v2BootID) bool {
	return v2BootPattern.MatchString(string(id)) && id != "00000000-0000-0000-0000-000000000000"
}

func validBootIntentV2(intent *v2CoordinatorIntent) bool {
	return intent != nil && intent.GuardDeadline == nil && intent.Kind == v2BootKind && intent.Recovery && intent.BootID != nil && validBootIDV2(*intent.BootID) && intent.Subject == "" && intent.OriginCommit == "" && intent.Lease == ""
}

func validFeaturesV2(state v2State) bool {
	last := ""
	for _, feature := range state.RequiredFeatures {
		if (feature != v2SharedReaderFeature && feature != v2BootFeature && feature != v2LocalFeature && feature != v2GuardDeadlineFeature && feature != v2RoutedFeature && feature != v2RoutedBootFeature && feature != v2RoutedNoNetworkFeature && feature != v2OwnedCandidateFeature && feature != v2RoutedBootBoundaryFeature) || feature <= last {
			return false
		}
		last = feature
	}
	if !validGuardDeadlineFeatureV2(state) || !validRoutedFeatureV2(state) {
		return false
	}
	if hasFeatureV2(state, v2RoutedBootFeature) && !hasFeatureV2(state, v2RoutedFeature) {
		return false
	}
	if hasFeatureV2(state, v2RoutedNoNetworkFeature) && !hasFeatureV2(state, v2RoutedBootFeature) {
		return false
	}
	if hasFeatureV2(state, v2OwnedCandidateFeature) && !hasFeatureV2(state, v2RoutedFeature) {
		return false
	}
	if hasFeatureV2(state, v2RoutedBootBoundaryFeature) && !hasFeatureV2(state, v2RoutedBootFeature) {
		return false
	}
	if cfg := state.Configuration; cfg != nil && cfg.Intent != nil && cfg.Intent.Kind == v2BootKind && cfg.Intent.Domain == "routed" && !hasFeatureV2(state, v2RoutedBootFeature) {
		return false
	}
	if state.Configuration != nil && (state.Configuration.LastCompletedBoot != "" || (state.Configuration.Intent != nil && state.Configuration.Intent.Kind == v2BootKind)) {
		if !hasFeatureV2(state, v2BootFeature) {
			return false
		}
	}
	if cfg := state.Configuration; cfg != nil && (cfg.LocalServices.Candidate != nil || (cfg.Pending != nil && cfg.Pending.Domain == "local_services") || (cfg.Intent != nil && cfg.Intent.Domain == "local_services")) {
		return hasFeatureV2(state, v2LocalFeature)
	}
	return true
}

func hasFeatureV2(state v2State, feature string) bool {
	for _, f := range state.RequiredFeatures {
		if f == feature {
			return true
		}
	}
	return false
}
func addFeatureV2(state *v2State, feature string) {
	if hasFeatureV2(*state, feature) {
		return
	}
	state.RequiredFeatures = append(state.RequiredFeatures, feature)
	sort.Strings(state.RequiredFeatures)
}

func preservesFeaturesV2(previous, next v2State) bool {
	if previous.Configuration != nil && next.Configuration != nil {
		p, n := previous.Configuration.Intent, next.Configuration.Intent
		if p != nil && n != nil && p.RoutedWork != "" {
			_, left, e1 := v2Canonical(p)
			_, right, e2 := v2Canonical(n)
			if e1 != nil || e2 != nil || left != right && !preservesRoutedBootBoundaryV2(previous, next) {
				return false
			}
		}
	}
	if !preservesGuardDeadlineV2(previous, next) {
		return false
	}
	for _, feature := range previous.RequiredFeatures {
		if !hasFeatureV2(next, feature) {
			return false
		}
	}
	return true
}

// This optional adapter is only assembled with the existing authenticated,
// one-time bootstrap verb. Normal Engine.Apply still requires a lease.
type startupBootstrapV2 interface {
	BootstrapStartup(context.Context, string, Revision) error
	ConfirmStartup(context.Context, string, Revision, Revision) error
}

// Marker 1 requires an original absolute deadline. Current real helpers stay
// gated until this trusted contract is implemented; legacy assembly is intact.
type startupDeadlineGuardV2 interface {
	ArmUntil(context.Context, string, Revision, Revision, time.Time) error
}

func (c *v2Coordinator) bootStartupLocked(ctx context.Context, id v2BootID) error {
	s := c.store
	routed := hasFeatureV2(s.state, v2RoutedFeature)
	if routed && c.options.Routed == nil {
		return ErrRecovery
	}
	if s.reserves != nil && !routed {
		for _, engine := range c.firewall {
			if guard, ok := engine.(ActivationGuard); ok {
				if _, absolute := guard.(startupDeadlineGuardV2); !absolute {
					return ErrRecovery
				}
			} else if _, bootstrap := engine.(startupBootstrapV2); bootstrap {
				return ErrRecovery
			}
		}
	}
	current := clone(*s.state.Configuration)
	if current.LastCompletedBoot != "" {
		var completed v2RecoveryRecord
		if s.readObject(current.LastCompletedBoot, &completed) != nil || !validRecoveryRecordV2(completed, s.state.Lineage) || completed.Kind != v2BootKind || completed.State != "final" {
			return ErrRecovery
		}
		if *completed.BootID == id {
			if routed && c.resumeRoutedLockedV2(ctx) != nil {
				return ErrRecovery
			}
			if !c.readback(current) {
				return ErrRecovery
			}
			return nil
		}
	}
	if c.bootBoundary != nil {
		current = routedBootBoundaryProjectionV2(current)
	}
	if current.Intent != nil || current.Pending != nil || current.RecoveryRequired || !routed && (current.LocalServices.Running.Hash != current.LocalServices.Startup.Hash || !c.localReadback(current)) {
		return ErrRecovery
	}
	if s.state.Generation == ^uint64(0) || current.Firewall.Generation == ^uint64(0) || s.used.Bytes+s.state.ReservedBytes+2*v2OperationReserveBytes > s.budget.Bytes || s.used.Inodes+s.state.ReservedInodes+2*v2OperationReserveInodes > s.budget.Inodes {
		return errV2Limited
	}
	if err := s.physicalCapacity(2*v2OperationReserveBytes, 2*v2OperationReserveInodes); err != nil {
		return err
	}
	target, err := bootTargetV2(current)
	if err != nil {
		return ErrInvalid
	}
	if !routed {
		for _, engine := range c.firewall {
			if engine.Validate(target.Firewall.Running.Config) != nil {
				return ErrEngine
			}
		}
	}
	if err := c.persistRevisions(target); err != nil {
		return err
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
	st := clone(s.state)
	if c.bootBoundary != nil {
		c.bootBoundary.NewOperation = issued
		st.RoutedBootBoundary = clone(c.bootBoundary)
		st.Configuration = clone(&current)
		if c.bootBoundary.Origin != nil {
			st.Configuration.Pending = clone(s.state.Configuration.Pending)
		}
		st.RoutedActive = nil
		if c.bootBoundary.OldBoot != nil {
			st.SystemBundle = nil
		}
		addFeatureV2(&st, v2RoutedBootBoundaryFeature)
	}
	bootIntent := v2CoordinatorIntent{Operation: issued, Domain: "firewall", Kind: v2BootKind, Previous: previousHash, Target: targetHash, TargetGeneration: st.Generation + 1, Recovery: true, BootID: &id}
	if routed {
		bootIntent.Domain = "routed"
		if err = c.publishRoutedBootWorkV2(ctx, record, current, target, &bootIntent); err != nil {
			return err
		}
	}
	if s.reserves != nil {
		if err = s.reserves.prepareBoot(s, &st, &record, bootIntent); err != nil {
			return err
		}
	}
	hash, err := s.object(record)
	if err != nil {
		return err
	}
	addFeatureV2(&st, v2BootFeature)
	if routed {
		addFeatureV2(&st, v2RoutedBootFeature)
		if target.Firewall.Running.Config.SchemaVersion == 4 {
			addFeatureV2(&st, v2RoutedNoNetworkFeature)
		}
	}
	st.Configuration.LastRecovery = hash
	st.Configuration.RecoveryIndex, err = c.recoveryIndexPut(st.Configuration.RecoveryIndex, record, hash)
	if err != nil {
		return err
	}
	st.Configuration.Intent = &bootIntent
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

func (c *v2Coordinator) finishBootLocked(ctx context.Context) (result error) {
	s := c.store
	defer func() {
		if result != nil && s.reserves != nil && s.state.SystemBundle != nil {
			if err := s.reserves.emergencyCandidate(s, s.state.SystemBundle.Bundle, "recovery_uncertain"); err != nil {
				result = ErrRecovery
			}
		}
	}()
	intent := s.state.Configuration.Intent
	if !validBootIntentV2(intent) || c.options.BootID == nil || *intent.BootID != *c.options.BootID || s.state.ReservedBytes < v2OperationReserveBytes || s.state.ReservedInodes < v2OperationReserveInodes {
		return ErrRecovery
	}
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = v2Budget{} }()
	var previous, target v2Configuration
	var record v2RecoveryRecord
	if s.readObject(intent.Previous, &previous) != nil || s.readObject(intent.Target, &target) != nil || !validBootTargetV2(previous, target) || s.readObject(s.state.Configuration.LastRecovery, &record) != nil || !validRecoveryRecordV2(record, s.state.Lineage) || record.ID != intent.Operation || record.Kind != v2BootKind || record.State != "pending" || *record.BootID != *intent.BootID || record.Previous != intent.Previous || record.Target != intent.Target || intent.TargetGeneration != s.state.Generation+1 {
		return ErrRecovery
	}
	if s.reserves != nil && s.reserves.verifyBundle(s, record.Reserve) != nil {
		return ErrRecovery
	}
	if _, err := c.bootRemainingV2(record); err != nil {
		return err
	}
	if intent.Domain != "routed" && !c.localReadback(target) {
		return ErrRecovery
	}
	// Recheck observed space on resumed work as well. The boot allowance is
	// owned by this intent; other operations' reservations remain protected.
	if err := s.physicalCapacity(v2OperationReserveBytes, v2OperationReserveInodes); err != nil {
		return err
	}
	if intent.Domain == "routed" {
		if err := c.applyRoutedBootV2(ctx, record, target); err != nil {
			return err
		}
	} else {
		for _, engine := range c.firewall {
			if _, err := c.bootRemainingV2(record); err != nil {
				return err
			}
			if engine.Validate(target.Firewall.Running.Config) != nil {
				return ErrEngine
			}
			if _, err := c.bootRemainingV2(record); err != nil {
				return err
			}
		}
		for _, engine := range c.firewall {
			current := engine.Current()
			if _, err := c.bootRemainingV2(record); err != nil {
				return err
			}
			if current == target.Firewall.Running.Hash {
				continue
			}
			if current == previous.Firewall.Running.Hash {
				if guard, ok := engine.(ActivationGuard); ok {
					if c.armBootGuardV2(ctx, guard, record, previous.Firewall.Running, target.Firewall.Running) != nil {
						return ErrRecovery
					}
					if _, err := c.bootRemainingV2(record); err != nil {
						return err
					}
					if engine.Apply(ctx, target.Firewall.Running) != nil || engine.Current() != target.Firewall.Running.Hash {
						return ErrRecovery
					}
				} else {
					if _, err := c.bootRemainingV2(record); err != nil {
						return err
					}
					if engine.Apply(ctx, target.Firewall.Running) != nil {
						return ErrEngine
					}
				}
			} else if bootstrap, ok := engine.(startupBootstrapV2); ok {
				if s.reserves != nil {
					return ErrRecovery
				}
				if _, err := c.bootRemainingV2(record); err != nil {
					return err
				}
				if bootstrap.BootstrapStartup(ctx, record.ID, target.Firewall.Running) != nil {
					return ErrRecovery
				}
			} else {
				return ErrRecovery
			}
			if err := c.point("after_boot_engine"); err != nil {
				return err
			}
			if _, err := c.bootRemainingV2(record); err != nil {
				return err
			}
		}
		if !c.readback(target) {
			return ErrRecovery
		}
		for _, engine := range c.firewall {
			if _, err := c.bootRemainingV2(record); err != nil {
				return err
			}
			if bootstrap, ok := engine.(startupBootstrapV2); ok && s.reserves == nil {
				if bootstrap.ConfirmStartup(ctx, record.ID, previous.Firewall.Running, target.Firewall.Running) != nil {
					return ErrRecovery
				}
			} else if guard, ok := engine.(ActivationGuard); ok {
				if c.armBootGuardV2(ctx, guard, record, previous.Firewall.Running, target.Firewall.Running) != nil {
					return ErrRecovery
				}
				if _, err := c.bootRemainingV2(record); err != nil {
					return err
				}
				if guard.Confirm(ctx, record.ID, target.Firewall.Running.Hash) != nil {
					return ErrRecovery
				}
			}
		}
	}
	if !c.readback(target) {
		return ErrRecovery
	}
	if err := c.point("after_boot_readback"); err != nil {
		return err
	}
	if _, err := c.bootRemainingV2(record); err != nil {
		return err
	}
	completed := c.recoveryNow()
	audit, err := c.appendAuditLocked(&target, record.ID, "", "", "system", v2BootKind, "verified", intent.TargetGeneration, completed)
	if err != nil {
		return err
	}
	target.VerifiedIndex, err = c.verifiedInsert(target.VerifiedIndex, 0, v2VerifiedEntry{Revision: target.Running.Hash, Audit: audit, Operation: record.ID})
	if err != nil {
		return err
	}
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
	if intent.Domain == "routed" {
		st.RoutedActive = &v2RoutedActive{Work: intent.RoutedWork, Side: "target"}
	}
	st.Generation = intent.TargetGeneration
	if st.SystemBundle != nil {
		st.SystemBundle.CanonicalHeld = true
	} else {
		st.ReservedBytes -= v2OperationReserveBytes
		st.ReservedInodes -= v2OperationReserveInodes
	}
	st.Clock = completed
	if err := c.point("before_boot_completion"); err != nil {
		return err
	}
	if _, err := c.bootRemainingV2(record); err != nil {
		return err
	}
	if err := s.publish(st); err != nil {
		return err
	}
	if s.reserves != nil {
		if err = s.reserves.maintainWork(s, record.ID); err != nil {
			return err
		}
	}
	return c.point("after_boot_completion")
}

func (c *v2Coordinator) bootRemainingV2(record v2RecoveryRecord) (time.Duration, error) {
	if c.store.reserves == nil {
		return 10 * time.Second, nil
	}
	now := c.now()
	deadline := record.Started.Add(10 * time.Second)
	if now.Before(record.Started) || now.Before(c.store.state.Clock) || !now.Before(deadline) {
		return 0, ErrRecovery
	}
	return deadline.Sub(now), nil
}

func (c *v2Coordinator) armBootGuardV2(ctx context.Context, guard ActivationGuard, record v2RecoveryRecord, previous, target Revision) error {
	remaining, err := c.bootRemainingV2(record)
	if err != nil {
		return err
	}
	if c.store.reserves != nil {
		absolute, ok := guard.(startupDeadlineGuardV2)
		if !ok {
			return ErrRecovery
		}
		if err = absolute.ArmUntil(ctx, record.ID, previous, target, record.Started.Add(10*time.Second)); err != nil {
			return ErrRecovery
		}
	} else if err = guard.Arm(ctx, record.ID, previous, target, remaining); err != nil {
		return ErrRecovery
	}
	_, err = c.bootRemainingV2(record)
	return err
}

func bootTargetV2(previous v2Configuration) (v2Configuration, error) {
	routed := previous.Running.Config.SchemaVersion == 7
	if !validV2Configuration(&previous) || previous.Intent != nil || previous.Pending != nil || previous.RecoveryRequired || previous.Firewall.Generation == ^uint64(0) || !routed && previous.LocalServices.Running.Hash != previous.LocalServices.Startup.Hash {
		return v2Configuration{}, ErrRecovery
	}
	target := clone(previous)
	target.Firewall.Running = target.Firewall.Startup
	target.Firewall.LastGood = target.Firewall.Startup
	target.Firewall.Generation++
	if routed {
		changed := target.LocalServices.Running.Hash != target.LocalServices.Startup.Hash || target.LocalServices.LastGood.Hash != target.LocalServices.Startup.Hash
		if changed && target.LocalServices.Generation == ^uint64(0) {
			return v2Configuration{}, errV2Limited
		}
		target.LocalServices.Running, target.LocalServices.LastGood = target.LocalServices.Startup, target.LocalServices.Startup
		if changed {
			target.LocalServices.Generation++
		}
	}
	if err := target.refresh(); err != nil {
		return v2Configuration{}, err
	}
	return target, nil
}

func validBootTargetV2(previous, target v2Configuration) bool {
	expected, err := bootTargetV2(previous)
	if err != nil || !validV2Configuration(&target) {
		return false
	}
	// The bounded canonical snapshot must preserve Candidate, Startup and all
	// other domain/history references, not just a matching Running hash.
	want, wantErr := json.Marshal(expected)
	got, gotErr := json.Marshal(target)
	return wantErr == nil && gotErr == nil && bytes.Equal(want, got)
}

package configpoc

import (
	"context"
	"os"
	"reflect"
	"time"
)

// An offline seed is declared configuration, not evidence of applied policy.
// Older readers must refuse it; runtime assembly must complete physical boot
// reconciliation before exposing any administrative readiness.
const v2RoutedOfflineSeedFeature = "configuration.routed-offline-seed.v1"

func declaredOfflineSeedV3(st v2State, cfg v2Configuration, load func(string, any) error) bool {
	if !hasFeatureV2(st, v2RoutedOfflineSeedFeature) || st.Generation != 1 || st.HighWater != 0 || st.RoutedActive != nil || cfg.VerifiedIndex != "" || cfg.AuditSequence != 1 || cfg.LastCompletedBoot != "" || cfg.Candidate != nil || cfg.CandidateGroup != nil || cfg.Pending != nil || cfg.RecoveryRequired || cfg.Firewall.Candidate != nil || cfg.LocalServices.Candidate != nil || cfg.Running.Hash != cfg.Startup.Hash || cfg.Running.Hash != cfg.LastGood.Hash || cfg.Firewall.Generation != 1 || cfg.LocalServices.Generation != 1 {
		return false
	}
	if cfg.Intent != nil && (!validBootIntentV2(cfg.Intent) || cfg.Intent.Domain != "routed") {
		return false
	}
	if cfg.Intent == nil && (cfg.LastRecovery != "" || cfg.RecoveryIndex != "") {
		return false
	}
	for _, domain := range []v2DomainSnapshot{cfg.Firewall, cfg.LocalServices} {
		if domain.Running.Hash != domain.Startup.Hash || domain.Running.Hash != domain.LastGood.Hash {
			return false
		}
	}
	fw, ls := cfg.Firewall.Running.Config, cfg.LocalServices.Running.Config
	if fw.SchemaVersion != 4 || len(fw.Rules) != 0 || ls.SchemaVersion != 3 || ls.LocalServices == nil || len(ls.Rules) != 0 || len(ls.LocalServices.Interfaces) != 0 || len(ls.LocalServices.Services) != 0 || load == nil {
		return false
	}
	var audit v2CoordinatorAudit
	return load(cfg.AuditTip, &audit) == nil && audit.Format == v2Format && audit.Kind == "offline_seed" && audit.Result == "prepared" && audit.Subject == "system" && audit.Sequence == 1 && audit.Generation == 1 && audit.Previous == "" && audit.OriginCommit == "" && audit.Lease == "" && audit.Operation != "" && audit.Running == cfg.Running.Hash && audit.Startup == cfg.Startup.Hash
}

// PrepareOfflineRoutedStoreV3 prepares a fresh, private, empty store only. It
// cannot migrate an existing appliance, invoke engines or publish verification.
// The installer owns pool lifetimes and the subsequent offline reader profile
// conversion. No handle returned here may be used as a shared-profile writer.
func PrepareOfflineRoutedStoreV3(ctx context.Context, area *os.Root, budget BudgetV2, pools RuntimePoolsV2, legacy, local Revision, subjects []SubjectV2, now time.Time) error {
	if ctx == nil || area == nil || now.IsZero() || len(subjects) == 0 || len(subjects) > v2MaximumSubjects {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	// Fresh installation starts closed. Existing policy/history must use the
	// separate fingerprint-bound migration path, never this seed constructor.
	fw, err := Canonical(legacy.Config)
	if err != nil || !reflect.DeepEqual(fw, legacy) || legacy.Config.SchemaVersion != 4 || legacy.Config.DefaultAction != "deny" || len(legacy.Config.Rules) != 0 {
		return ErrInvalid
	}
	ls, err := Canonical(local.Config)
	if err != nil || !reflect.DeepEqual(ls, local) || local.Config.SchemaVersion != 3 || len(local.Config.Rules) != 0 || local.Config.LocalServices == nil || len(local.Config.LocalServices.Services) != 0 || len(local.Config.LocalServices.Interfaces) != 0 {
		return ErrInvalid
	}
	manager, err := newReserveManagerV2(pools.Admission, pools.Plan, pools.Emergency)
	if err != nil {
		return err
	}
	lineage, err := v2ID("lineage", 1)
	if err != nil {
		return err
	}
	domain := func(r Revision) v2DomainSnapshot {
		return v2DomainSnapshot{Generation: 1, Running: clone(r), Startup: clone(r), LastGood: clone(r)}
	}
	cfg := v2Configuration{Firewall: domain(fw), LocalServices: domain(ls)}
	cfg.Running.Config.SchemaVersion = 7
	if cfg.refresh() != nil || !validV2Configuration(&cfg) {
		return ErrInvalid
	}
	state := v2State{Format: v2Format, Lineage: lineage, Generation: 1, LiveSlots: v2MaximumOperations, Subjects: clone(subjects), Namespaces: []v2Namespace{}, Clock: now.UTC(), RecoveryReserveVersion: 1, Configuration: &cfg}
	for _, feature := range []string{v2RoutedOfflineSeedFeature, v2RoutedFeature, v2GuardDeadlineFeature, v2SharedReaderFeature} {
		addFeatureV2(&state, feature)
	}
	s, err := prepareV2(area, v2Budget{Bytes: budget.Bytes, Inodes: budget.Inodes}, state)
	if err != nil {
		return err
	}
	defer s.close()
	s.reserves = manager
	if err = manager.verifySelected(s); err != nil {
		return err
	}
	c := &v2Coordinator{store: s}
	if err = c.persistRevisions(cfg); err != nil {
		return err
	}
	operation, err := v2ID("offline-seed", 1)
	if err != nil {
		return err
	}
	if _, err = c.appendAuditLocked(&cfg, operation, "", "", "system", "offline_seed", "prepared", 1, now.UTC()); err != nil {
		return err
	}
	state = s.state
	state.Configuration = &cfg
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	// This is the same one-way private-to-shared publication seam used by the
	// cold installer. The private handle is closed before callers change ACLs.
	s.preparingShared = true
	return s.publish(state)
}

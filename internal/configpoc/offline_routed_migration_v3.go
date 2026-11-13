package configpoc

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

const v2RoutedOfflineMigrationFeature = "configuration.routed-offline-migration.v1"

// OfflineMigrationReadbackV3 is provided only by trusted installer assembly.
// It must inspect the pinned former firewall helper's effective rules and the
// absence of managed local-service resources. Comparing supplied hashes or
// accepting a caller's assertion is not an implementation of this contract.
// The installer holds both source domains quiescent until preparation returns.
// The callback must not enter the destination store, whose writer lock is held.
type OfflineMigrationReadbackV3 interface {
	VerifyMigratedSources(context.Context, [2]LegacyFingerprintV2, Revision, Revision) error
}

// PrepareOfflineMigratedRoutedStoreV3 upgrades a prepared, private migration.
// It preserves imported history and records verified source policy, not proof
// that the new gateway has applied it. The selected feature requires physical
// boot reconciliation before runtime readiness. Profile conversion is a
// separate offline installer step; no engine or permissions are changed here.
func PrepareOfflineMigratedRoutedStoreV3(ctx context.Context, area *os.Root, sources [2]*os.Root, budget BudgetV2, pools RuntimePoolsV2, expected [2]LegacyFingerprintV2, readback OfflineMigrationReadbackV3, now time.Time) error {
	return prepareOfflineMigratedRoutedStoreV3(ctx, area, sources, budget, pools, expected, readback, now, nil)
}

func prepareOfflineMigratedRoutedStoreV3(ctx context.Context, area *os.Root, sources [2]*os.Root, budget BudgetV2, pools RuntimePoolsV2, expected [2]LegacyFingerprintV2, readback OfflineMigrationReadbackV3, now time.Time, hook func(string) error) (result error) {
	if ctx == nil || area == nil || sources[0] == nil || sources[1] == nil || readback == nil || now.IsZero() || expected[0].Domain != "firewall" || expected[1].Domain != "local_services" {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	manager, err := newReserveManagerV2(pools.Admission, pools.Plan, pools.Emergency)
	if err != nil {
		return err
	}
	// Hold source locks before the destination, matching PrepareMigrationV2.
	// A change in the interval after copying invalidates this upgrade; it never
	// silently recopies or rebinds the history selected by the operator.
	if !offlineMigrationSeparateV3([3]*os.Root{sources[0], sources[1], area}) {
		return ErrInvalid
	}
	fwLock, err := lockLegacyV2(sources[0])
	if err != nil {
		return err
	}
	defer func() {
		if err := fwLock.Close(); err != nil && result == nil {
			result = err
		}
	}()
	lsLock, err := lockLegacyV2(sources[1])
	if err != nil {
		return err
	}
	defer func() {
		if err := lsLock.Close(); err != nil && result == nil {
			result = err
		}
	}()
	for i, domain := range []string{"firewall", "local_services"} {
		image, err := inspectLegacyV2(sources[i], domain, nil)
		if err != nil {
			return err
		}
		if fingerprintLegacyV2(image) != expected[i] {
			return ErrConflict
		}
	}

	s, err := openV2(area, v2Budget{Bytes: budget.Bytes, Inodes: budget.Inodes})
	if err != nil {
		return err
	}
	defer func() {
		if err := s.close(); err != nil && result == nil {
			result = err
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hook = hook
	st := clone(s.state)
	// This is an upgrade of the unactivated migration, not a replacement of
	// existing configuration, operations, accounting or recovery authority.
	if st.Migration == "" || st.Configuration != nil || st.Operational || st.HighWater != 0 || len(st.Namespaces) != 0 || st.RecoveryReserveVersion != 0 || len(st.RequiredFeatures) != 0 || st.ReclamationVersion != 0 || now.UTC().Before(st.Clock) {
		return ErrConflict
	}
	var imported v2Migration
	if s.validateMigration() != nil || s.readObject(st.Migration, &imported) != nil {
		return ErrRecovery
	}
	if fingerprintLegacyV2(imported.Firewall) != expected[0] || fingerprintLegacyV2(imported.LocalServices) != expected[1] {
		return ErrConflict
	}
	for _, image := range []v2LegacyImage{imported.Firewall, imported.LocalServices} {
		snap := image.Snapshot
		if snap.Candidate != nil || snap.Pending != nil || snap.RecoveryRequired || snap.Running.Hash != snap.Startup.Hash || snap.Running.Hash != snap.LastGood.Hash {
			return ErrConflict
		}
	}
	fw, ls := imported.Firewall.Snapshot.Running, imported.LocalServices.Snapshot.Running
	if fw.Config.SchemaVersion != 4 || ls.Config.SchemaVersion != 3 || ls.Config.DefaultAction != "deny" || len(ls.Config.Rules) != 0 || ls.Config.LocalServices == nil || len(ls.Config.LocalServices.Interfaces) != 0 || len(ls.Config.LocalServices.Services) != 0 {
		return ErrInvalid
	}
	if err = manager.verifySelected(s); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	if err = readback.VerifyMigratedSources(ctx, expected, clone(fw), clone(ls)); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	from := func(image v2LegacyImage) v2DomainSnapshot {
		return v2DomainSnapshot{Generation: image.Projection, Running: clone(image.Snapshot.Running), Startup: clone(image.Snapshot.Startup), LastGood: clone(image.Snapshot.LastGood)}
	}
	cfg := v2Configuration{Firewall: from(imported.Firewall), LocalServices: from(imported.LocalServices)}
	cfg.Running.Config.SchemaVersion = 7
	if cfg.refresh() != nil || !validV2Configuration(&cfg) {
		return ErrInvalid
	}
	c := &v2Coordinator{store: s}
	if err = c.persistRevisions(cfg); err != nil {
		return err
	}
	operation, err := v2ID("initialize", s.selection.Sequence+1)
	if err != nil {
		return err
	}
	audit, err := c.appendAuditLocked(&cfg, operation, "", "", "system", "initialize", "verified", st.Generation, now.UTC())
	if err != nil {
		return err
	}
	cfg.VerifiedIndex, err = c.verifiedInsert("", 0, v2VerifiedEntry{Revision: cfg.Running.Hash, Audit: audit, Operation: operation})
	if err != nil {
		return err
	}
	st.Configuration = &cfg
	st.RecoveryReserveVersion = 1
	st.Clock = now.UTC()
	for _, feature := range []string{v2RoutedOfflineMigrationFeature, v2RoutedFeature, v2GuardDeadlineFeature, v2SharedReaderFeature} {
		addFeatureV2(&st, feature)
	}
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	s.reserves = manager
	s.preparingShared = true
	return s.publish(st)
}

// All three roots already exist. Unlike checkCheckpointArea, this check does
// not require the destination to use the older checkpoint directory layout.
// Ancestry is compared by inode identity as well as canonical path spelling.
func offlineMigrationSeparateV3(roots [3]*os.Root) bool {
	var identities [3]os.FileInfo
	for i, root := range roots {
		name := root.Name()
		if !filepath.IsAbs(name) || filepath.Clean(name) != name || name == string(filepath.Separator) {
			return false
		}
		opened, err := root.Stat(".")
		if err != nil || !opened.IsDir() || opened.Mode().Perm() != 0700 || !owned(opened) {
			return false
		}
		named, err := os.Lstat(name)
		if err != nil || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(named, opened) {
			return false
		}
		identities[i] = opened
	}
	for i, root := range roots {
		for path := root.Name(); ; path = filepath.Dir(path) {
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return false
			}
			for j, other := range identities {
				if i != j && os.SameFile(info, other) {
					return false
				}
			}
			if path == filepath.Dir(path) {
				break
			}
		}
	}
	return true
}

package configpoc

import (
	"context"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

const v4RoutedRebootScopeFeature = "configuration.routed-reboot-scope.v4"

// Each timestamp belongs to the BootID named by its field. Old BOOTTIME is
// historical evidence only; it cannot establish remaining lease life now.
type RoutedRebootScopeEvidenceV4 struct {
	Version             int                                    `json:"version"`
	Old                 networkexecutor.OwnedNamespaceIdentity `json:"old"`
	New                 networkexecutor.OwnedNamespaceIdentity `json:"new"`
	Work                string                                 `json:"work"`
	ReceiptSHA256       string                                 `json:"receipt_sha256"`
	MetadataSHA256      string                                 `json:"metadata_sha256"`
	DrainedAtOldBootNS  int64                                  `json:"drained_at_old_boot_ns"`
	ObservedAtNewBootNS int64                                  `json:"observed_at_new_boot_ns"`
	Before              string                                 `json:"before"`
	Dependencies        string                                 `json:"dependencies"`
}

func ValidRoutedRebootScopeEvidenceV4(e RoutedRebootScopeEvidenceV4) bool {
	return e.Version == 4 && validRoutedIdentityV1(e.Old) && validRoutedIdentityV1(e.New) && e.Old.BootID != e.New.BootID && e.Old.RunID != e.New.RunID && e.Old.UID == e.New.UID && e.Old.GID == e.New.GID && validHash(e.Work) && validHash(e.ReceiptSHA256) && validHash(e.MetadataSHA256) && validHash(e.Before) && validHash(e.Dependencies) && e.DrainedAtOldBootNS > 0 && e.ObservedAtNewBootNS > 0
}

type RoutedRebootScopeAuthorityV4 interface {
	ProveRebootScope(context.Context, string) (RoutedRebootScopeEvidenceV4, error)
}

func rebootScopeMatchesV4(e *RoutedRebootScopeEvidenceV4, old, next networkexecutor.OwnedNamespaceIdentity, work string) bool {
	return e != nil && ValidRoutedRebootScopeEvidenceV4(*e) && e.Old == old && e.New == next && e.Work == work
}

func (c *v2Coordinator) proveRebootScopeV4(ctx context.Context, old networkexecutor.OwnedNamespaceIdentity, work string) (*RoutedRebootScopeEvidenceV4, error) {
	if c.options.RebootScope == nil || c.options.Routed == nil || c.options.Routed.Identity() != c.options.RoutedIdentity {
		return nil, ErrRecovery
	}
	e, err := c.options.RebootScope.ProveRebootScope(ctx, work)
	if err != nil || ctx.Err() != nil || !rebootScopeMatchesV4(&e, old, c.options.RoutedIdentity, work) {
		return nil, ErrRecovery
	}
	return &e, nil
}

func (c *v2Coordinator) proveScopeRetirementV4(ctx context.Context, old networkexecutor.OwnedNamespaceIdentity, work string) (*RoutedFreshScopeEvidenceV3, *RoutedRebootScopeEvidenceV4, error) {
	if old.BootID != c.options.RoutedIdentity.BootID {
		p, err := c.proveRebootScopeV4(ctx, old, work)
		return nil, p, err
	}
	p, err := c.proveFreshScopeV3(ctx, old, work)
	return p, nil, err
}

// Internal comparisons share code, not authority. This representation is never
// persisted or returned; validation remains strict for each separate profile.
type routedScopeComparisonV4 struct {
	old, next                                     networkexecutor.OwnedNamespaceIdentity
	work, receipt, metadata, before, dependencies string
	drained, observed                             int64
	reboot                                        bool
}

func compareScopeV4(f *RoutedFreshScopeEvidenceV3, b *RoutedRebootScopeEvidenceV4) (routedScopeComparisonV4, bool) {
	if f != nil && b == nil && ValidRoutedFreshScopeEvidenceV3(*f) {
		return routedScopeComparisonV4{old: f.Old, next: f.New, work: f.Work, receipt: f.ReceiptSHA256, metadata: f.MetadataSHA256, before: f.Before, dependencies: f.Dependencies, drained: f.DrainedAtBootNS, observed: f.ObservedAtBootNS}, true
	}
	if b != nil && f == nil && ValidRoutedRebootScopeEvidenceV4(*b) {
		return routedScopeComparisonV4{old: b.Old, next: b.New, work: b.Work, receipt: b.ReceiptSHA256, metadata: b.MetadataSHA256, before: b.Before, dependencies: b.Dependencies, drained: b.DrainedAtOldBootNS, observed: b.ObservedAtNewBootNS, reboot: true}, true
	}
	return routedScopeComparisonV4{}, false
}

// Metadata only: Old is supplied by the authenticated root receipt. G1/R2
// selects the exact old work; the helper still proves physical absence later.
func (r *RoutedSelectionReaderV2) PrepareRebootScopeViewV4(ctx context.Context, old networkexecutor.OwnedNamespaceIdentity) (RoutedServiceRestartViewV3, error) {
	var out RoutedServiceRestartViewV3
	if r == nil || r.options.Policy != SelectionFullHistoryV2 || !validRoutedIdentityV1(old) || old.BootID == r.options.Identity.BootID {
		return out, ErrRecovery
	}
	_, err := r.observeScopeV4(ctx, "", true, func(source RoutedFreshScopeSourceV3, _ RoutedPrepareViewV2) error {
		if source.Identity() != old {
			return ErrRecovery
		}
		out.Target, out.Saved = source.PreparationBundles()
		out.Work = source.Reference().WorkHash
		return nil
	})
	if err != nil {
		return RoutedServiceRestartViewV3{}, err
	}
	return out, nil
}

func (r *RoutedSelectionReaderV2) ObserveRebootScopeV4(ctx context.Context, work string, observe func(RoutedFreshScopeSourceV3, RoutedPrepareViewV2) error) (RoutedFreshScopeSourceV3, error) {
	if !validHash(work) {
		return RoutedFreshScopeSourceV3{}, ErrRecovery
	}
	return r.observeScopeV4(ctx, work, true, observe)
}

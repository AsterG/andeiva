package configpoc

import (
	"context"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

const v3RoutedFreshScopeFeature = "configuration.routed-fresh-scope.v3"

// RoutedFreshScopeEvidenceV3 records a trusted helper's root-receipt and fresh
// kernel observation. Persisted bytes are historical evidence, not authority to
// adopt addresses or reopen tokens. Only FreshScope.ProveFreshScope may issue a
// new transition; no operation request accepts this structure.
type RoutedFreshScopeEvidenceV3 struct {
	Version          int                                    `json:"version"`
	Old              networkexecutor.OwnedNamespaceIdentity `json:"old"`
	New              networkexecutor.OwnedNamespaceIdentity `json:"new"`
	Work             string                                 `json:"work"`
	ReceiptSHA256    string                                 `json:"receipt_sha256"`
	MetadataSHA256   string                                 `json:"metadata_sha256"`
	DrainedAtBootNS  int64                                  `json:"drained_at_boot_ns"`
	ObservedAtBootNS int64                                  `json:"observed_at_boot_ns"`
	Before           string                                 `json:"before"`
	Dependencies     string                                 `json:"dependencies"`
}

func ValidRoutedFreshScopeEvidenceV3(e RoutedFreshScopeEvidenceV3) bool {
	return e.Version == 3 && validRoutedIdentityV1(e.Old) && validRoutedIdentityV1(e.New) &&
		e.Old.BootID == e.New.BootID && e.Old.Host == e.New.Host && e.Old.UID == e.New.UID && e.Old.GID == e.New.GID &&
		e.Old.RunID != e.New.RunID && e.Old.Namespace != e.New.Namespace &&
		validHash(e.Work) && validHash(e.ReceiptSHA256) && validHash(e.MetadataSHA256) && validHash(e.Before) && validHash(e.Dependencies) &&
		e.DrainedAtBootNS > 0 && e.ObservedAtBootNS >= e.DrainedAtBootNS
}

// This capability is installed only by trusted runtime assembly. The helper
// resolves the work independently and checks its fixed inherited root receipt.
type RoutedFreshScopeAuthorityV3 interface {
	ProveFreshScope(context.Context, string) (RoutedFreshScopeEvidenceV3, error)
}

func freshScopeMatchesV3(e *RoutedFreshScopeEvidenceV3, old, next networkexecutor.OwnedNamespaceIdentity, work string) bool {
	return e != nil && ValidRoutedFreshScopeEvidenceV3(*e) && e.Old == old && e.New == next && e.Work == work
}

func (c *v2Coordinator) proveFreshScopeV3(ctx context.Context, old networkexecutor.OwnedNamespaceIdentity, work string) (*RoutedFreshScopeEvidenceV3, error) {
	if c.options.FreshScope == nil || c.options.Routed == nil || c.options.Routed.Identity() != c.options.RoutedIdentity {
		return nil, ErrRecovery
	}
	e, err := c.options.FreshScope.ProveFreshScope(ctx, work)
	if err != nil || ctx.Err() != nil || !freshScopeMatchesV3(&e, old, c.options.RoutedIdentity, work) {
		return nil, ErrRecovery
	}
	return &e, nil
}

// RoutedFreshScopeSourceV3 is issued only by a full selected reader. Its old
// identity cannot be supplied by an API request or inferred from matching IPs.
type RoutedFreshScopeSourceV3 struct {
	identity      networkexecutor.OwnedNamespaceIdentity
	ref           SelectionReferenceV2
	target, saved RoutedActivationBundleV1
}

func (s RoutedFreshScopeSourceV3) Identity() networkexecutor.OwnedNamespaceIdentity {
	return s.identity
}
func (s RoutedFreshScopeSourceV3) Reference() SelectionReferenceV2 { return s.ref }
func (s RoutedFreshScopeSourceV3) PreparationBundles() (RoutedActivationBundleV1, RoutedActivationBundleV1) {
	return clone(s.target), clone(s.saved)
}

func (r *RoutedSelectionReaderV2) ResolveFreshScopeSourceV3(ctx context.Context, work string) (out RoutedFreshScopeSourceV3, result error) {
	return r.ObserveFreshScopeV3(ctx, work, func(RoutedFreshScopeSourceV3, RoutedPrepareViewV2) error { return nil })
}

// ObserveFreshScopeV3 retains one complete G1/R2 read through a trusted readonly
// kernel observation, then revalidates selector, objects and pool bindings. The
// callback must not reenter this reader or apply effects. It is never wire data.
func (r *RoutedSelectionReaderV2) ObserveFreshScopeV3(ctx context.Context, work string, observe func(RoutedFreshScopeSourceV3, RoutedPrepareViewV2) error) (out RoutedFreshScopeSourceV3, result error) {
	if r == nil || r.options.Policy != SelectionFullHistoryV2 || !validHash(work) || observe == nil {
		return out, ErrRecovery
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.read(ctx)
	if err != nil {
		return out, err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			out, result = RoutedFreshScopeSourceV3{}, ErrRecovery
		}
	}()
	s := v.store
	var old networkexecutor.OwnedNamespaceIdentity
	if d := s.state.RoutedDHCP; d != nil && d.Work == work {
		w, e := loadRoutedDHCPWorkV3(work, s.state.Lineage, s.readObject)
		if e != nil || validateRoutedDHCPSelectedV3(s.state, s.readObject) != nil {
			return out, ErrRecovery
		}
		old = w.Snapshot.Identity
	} else {
		selected := false
		cfg := s.state.Configuration
		if cfg == nil {
			return out, ErrRecovery
		}
		if in := cfg.Intent; in != nil && in.Kind == v2BootKind && in.Domain == "routed" && in.RoutedWork == work {
			selected = true
		} else if p := cfg.Pending; p != nil && p.Domain == "routed" && cfg.Intent == nil {
			op, e := s.lookupRetained(p.Owner, p.OriginCommit)
			selected = e == nil && op.Pinned && op.Reserve != nil && op.Reserve.PlanIntent != nil && op.Reserve.PlanIntent.RoutedWork == work
		} else if cfg.Intent == nil && cfg.Pending == nil && s.state.RoutedActive != nil {
			selected = s.state.RoutedActive.Work == work
		}
		if !selected {
			return out, ErrRecovery
		}
		p, e := loadRoutedWorkV2(work, s.state.Lineage, s.readObject)
		if e != nil {
			return out, ErrRecovery
		}
		old = p.Scope().Identity
	}
	if old == r.options.Identity || old.BootID != r.options.Identity.BootID || old.RunID == r.options.Identity.RunID || old.Namespace == r.options.Identity.Namespace || old.UID != r.options.Identity.UID || old.GID != r.options.Identity.GID || old.Host != r.options.Identity.Host {
		return out, ErrRecovery
	}
	ref := v.ref
	ref.WorkHash = work
	out = RoutedFreshScopeSourceV3{identity: old, ref: ref}
	view, err := routedPrepareViewFromStoreV2(v.store)
	if err != nil {
		return RoutedFreshScopeSourceV3{}, err
	}
	if addServiceRestartViewV3(s, r.options.Identity, &view) != nil || view.ServiceRestart == nil {
		return RoutedFreshScopeSourceV3{}, ErrRecovery
	}
	out.target, out.saved = view.ServiceRestart.Target, view.ServiceRestart.Saved
	if err = observe(out, view); err != nil {
		return RoutedFreshScopeSourceV3{}, err
	}
	if err = r.revalidate(ctx, v); err != nil {
		return RoutedFreshScopeSourceV3{}, err
	}
	return out, nil
}

package configpoc

import (
	"context"
	"os"
	"sync"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

// SelectionReferenceV2 is correlation, never authority. Every field is checked
// against a fresh canonical selection; identity comes only from trusted options.
type SelectionReferenceV2 struct {
	Selection  string `json:"selection"`
	Previous   string `json:"previous"`
	State      string `json:"state"`
	Lineage    string `json:"lineage"`
	Sequence   uint64 `json:"sequence,string"`
	Generation uint64 `json:"generation,string"`
	WorkHash   string `json:"work_hash,omitempty"`
	Mode       string `json:"mode"`
}

type SelectionReadBudgetV2 = v2ReachabilityBudget

type RoutedSelectionPurposeV2 string

const (
	SelectionArmV2         RoutedSelectionPurposeV2 = "arm"
	SelectionApplyV2       RoutedSelectionPurposeV2 = "apply"
	SelectionConfirmV2     RoutedSelectionPurposeV2 = "confirm"
	SelectionRecoverV2     RoutedSelectionPurposeV2 = "recover"
	SelectionBootstrapV2   RoutedSelectionPurposeV2 = "bootstrap"
	SelectionResumeV2      RoutedSelectionPurposeV2 = "resume"
	SelectionMatchBeforeV2 RoutedSelectionPurposeV2 = "match_before"
	SelectionMatchTargetV2 RoutedSelectionPurposeV2 = "match_target"
)

type SelectionReaderOptionsV2 struct {
	Access                     recoveryreserve.ReaderAccessV2
	Identity                   networkexecutor.OwnedNamespaceIdentity
	Admission, Plan, Emergency *recoveryreserve.ReadOnlyPoolV2
	Budget                     SelectionReadBudgetV2
}

// RoutedSelectionReaderV2 borrows all roots/pools. It opens no writer, takes no
// store flock and performs no cleanup, publication or engine call. The caller
// must retain the single-writer publication/incarnation barrier through effects.
type RoutedSelectionReaderV2 struct {
	mu      sync.Mutex
	area    *os.Root
	options SelectionReaderOptionsV2
}

type selectedViewV2 struct {
	store *v2Store
	graph *v2ReachabilityReader
	ref   SelectionReferenceV2
	pools [3]recoveryreserve.PoolSnapshotV2
}

func NewRoutedSelectionReaderV2(area *os.Root, options SelectionReaderOptionsV2) (*RoutedSelectionReaderV2, error) {
	if area == nil || !validRoutedIdentityV1(options.Identity) || options.Identity.UID == options.Access.OwnerUID || options.Admission == nil || options.Plan == nil || options.Emergency == nil || options.Admission == options.Plan || options.Plan == options.Emergency || options.Admission == options.Emergency || !validReachabilityBudgetV2(options.Budget) || options.Access.CheckDirectory(area) != nil {
		return nil, ErrInvalid
	}
	return &RoutedSelectionReaderV2{area: area, options: options}, nil
}

func (r *RoutedSelectionReaderV2) pools() [3]*recoveryreserve.ReadOnlyPoolV2 {
	return [3]*recoveryreserve.ReadOnlyPoolV2{r.options.Admission, r.options.Plan, r.options.Emergency}
}

func (r *RoutedSelectionReaderV2) read(ctx context.Context) (*selectedViewV2, error) {
	if ctx == nil || ctx.Err() != nil || r.area == nil || r.options.Access.CheckDirectory(r.area) != nil {
		return nil, ErrRecovery
	}
	if _, err := r.area.Lstat("selection.pending"); !os.IsNotExist(err) {
		return nil, ErrRecovery
	}
	graph := &v2ReachabilityReader{ctx: ctx, area: r.area, budget: r.options.Budget, objects: map[string]bool{}, edges: map[string]uint8{}, shared: &r.options.Access}
	s := &v2Store{root: r.area, access: &r.options.Access, readOnly: true, recordReader: graph.storeRecordV2, objectReader: graph.object}
	view := &selectedViewV2{store: s, graph: graph}
	manager := &v2ReserveManager{readers: map[recoveryreserve.RoleV2]reserveReadPoolV2{}}
	for i, pool := range r.pools() {
		snapshot, err := pool.Snapshot(ctx)
		if err != nil {
			return nil, ErrRecovery
		}
		profile, err := snapshot.Profile()
		if err != nil {
			return nil, ErrRecovery
		}
		view.pools[i] = snapshot
		manager.readers[profile.Role] = snapshot
	}
	s.reserves = manager
	if err := s.readSelection(); err != nil {
		return nil, err
	}
	if s.state.Configuration == nil || s.state.RecoveryReserveVersion != 1 || !hasFeatureV2(s.state, v2SharedReaderFeature) || !hasFeatureV2(s.state, v2RoutedFeature) {
		return nil, ErrRecovery
	}
	if err := graph.selection(s.selector.Current, &s.selector.Previous); err != nil {
		return nil, err
	}
	if s.selector.Previous != "" {
		if err := graph.selection(s.selector.Previous, nil); err != nil {
			return nil, err
		}
	}
	if manager.verifySelected(s) != nil || validateRoutedActiveV2(s.state, s.readObject) != nil {
		return nil, ErrRecovery
	}
	ref := SelectionReferenceV2{Selection: s.selector.Current, Previous: s.selector.Previous, State: s.selection.State, Lineage: s.state.Lineage, Sequence: s.selection.Sequence, Generation: s.state.Generation, Mode: "prepare"}
	if intent := s.state.Configuration.Intent; intent != nil {
		if intent.Domain != "routed" || !validHash(intent.RoutedWork) {
			return nil, ErrRecovery
		}
		ref.WorkHash, ref.Mode = intent.RoutedWork, "intent"
	} else if s.state.Configuration.Pending != nil {
		ref.Mode = "pending"
		_, pendingWork, err := selectedPendingReadbackV2(s)
		if err != nil {
			return nil, err
		}
		ref.WorkHash = pendingWork
	} else if active := s.state.RoutedActive; active != nil {
		ref.WorkHash, ref.Mode = active.Work, "active"
	}
	view.ref = ref
	if err := r.revalidate(ctx, view); err != nil {
		return nil, err
	}
	return view, nil
}

func (r *RoutedSelectionReaderV2) revalidate(ctx context.Context, v *selectedViewV2) error {
	if ctx.Err() != nil || r.options.Access.CheckDirectory(r.area) != nil {
		return ErrRecovery
	}
	for i, pool := range r.pools() {
		if pool.Revalidate(ctx, v.pools[i]) != nil {
			return ErrRecovery
		}
	}
	data, err := v.store.readRecordV2("selected.json", 4096)
	var selector v2Selector
	if err != nil || checkpointDecode(data, &selector) != nil || selector != v.store.selector || ctx.Err() != nil {
		return ErrRecovery
	}
	if _, err = r.area.Lstat("selection.pending"); !os.IsNotExist(err) {
		return ErrRecovery
	}
	return nil
}

func (r *RoutedSelectionReaderV2) Observe(ctx context.Context) (SelectionReferenceV2, error) {
	if r == nil || ctx == nil {
		return SelectionReferenceV2{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.read(ctx)
	if err != nil {
		return SelectionReferenceV2{}, err
	}
	return v.ref, nil
}

func (r *RoutedSelectionReaderV2) Resolve(ctx context.Context, reference SelectionReferenceV2, purpose RoutedSelectionPurposeV2) (RoutedSelectedPlanV1, error) {
	if r == nil || ctx == nil {
		return RoutedSelectedPlanV1{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.read(ctx)
	if err != nil {
		return RoutedSelectedPlanV1{}, err
	}
	if v.ref != reference {
		return RoutedSelectedPlanV1{}, ErrConflict
	}
	var plan RoutedSelectedPlanV1
	s := v.store
	switch reference.Mode {
	case "intent":
		plan, err = selectedRoutedPlanFromStoreV2(s, r.options.Identity)
	case "pending":
		plan, _, err = selectedPendingReadbackV2(s)
		if err == nil && plan.Scope().Identity != r.options.Identity {
			return RoutedSelectedPlanV1{}, ErrRecovery
		}
	case "active":
		if s.state.Configuration.RecoveryRequired {
			return plan, ErrRecovery
		}
		plan, err = loadRoutedWorkV2(reference.WorkHash, s.state.Lineage, s.readObject)
		if err == nil && plan.Scope().Identity != r.options.Identity {
			return RoutedSelectedPlanV1{}, ErrRecovery
		}
		if err == nil {
			plan.resolution = s.state.RoutedActive.Side
		}
	default:
		return plan, ErrRecovery
	}
	if err != nil {
		return RoutedSelectedPlanV1{}, err
	}
	if !selectedPurposeV2(s, plan, purpose) {
		return RoutedSelectedPlanV1{}, ErrDenied
	}
	if err = r.revalidate(ctx, v); err != nil {
		return RoutedSelectedPlanV1{}, err
	}
	return plan, nil
}

func selectedPurposeV2(s *v2Store, plan RoutedSelectedPlanV1, purpose RoutedSelectionPurposeV2) bool {
	if s == nil || s.state.Configuration == nil || !plan.Valid() {
		return false
	}
	cfg := s.state.Configuration
	in := cfg.Intent
	if purpose == SelectionMatchBeforeV2 || purpose == SelectionMatchTargetV2 {
		return in != nil || s.state.RoutedActive != nil || cfg.Pending != nil
	}
	if purpose == SelectionResumeV2 {
		return in == nil && cfg.Pending == nil && !cfg.RecoveryRequired && s.state.RoutedActive != nil
	}
	if in == nil || in.Domain != "routed" {
		return false
	}
	boot := in.Kind == v2BootKind && validBootIntentV2(in) && plan.Cold() && plan.bootRecord != nil && routedBootRecordMatchesV2(plan, *plan.bootRecord)
	ordinary := !in.Recovery && (in.Kind == OpCommit || in.Kind == OpRollback)
	confirm := !in.Recovery && in.Kind == OpConfirm
	if ordinary || confirm {
		op, err := s.lookupRetained(in.Subject, in.Operation)
		if err != nil || op.Domain != "routed" || op.Request.Kind != in.Kind || op.State == "final" {
			return false
		}
		if ordinary && (op.Request.ConfirmSeconds == nil || *op.Request.ConfirmSeconds < 30 || *op.Request.ConfirmSeconds > 120) {
			return false
		}
	}
	switch purpose {
	case SelectionArmV2, SelectionApplyV2:
		return ordinary
	case SelectionConfirmV2:
		return confirm || boot
	case SelectionBootstrapV2:
		return boot
	case SelectionRecoverV2:
		// Existing failed-operation compensation uses its original selected
		// intent; timeout/restart recovery uses an explicit recovery intent.
		// Both remain bound to the original plan and exact guardian receipt.
		return !boot && (in.Recovery || ordinary || confirm)
	default:
		return false
	}
}

// Pending work is readback-only. Its original selected plan is retained by the
// pinned operation and reserve; a prior Active plan cannot stand in for it.
func selectedPendingReadbackV2(s *v2Store) (RoutedSelectedPlanV1, string, error) {
	p := s.state.Configuration.Pending
	if p == nil || p.Domain != "routed" || s.state.Configuration.Intent != nil || s.state.Configuration.RecoveryRequired {
		return RoutedSelectedPlanV1{}, "", ErrRecovery
	}
	op, err := s.lookupRetained(p.Owner, p.OriginCommit)
	if err != nil || op.Domain != "routed" || op.State != "final" || !op.Pinned || op.Reserve == nil || op.Reserve.PlanIntent == nil {
		return RoutedSelectedPlanV1{}, "", ErrRecovery
	}
	hash := op.Reserve.PlanIntent.RoutedWork
	plan, err := loadRoutedWorkV2(hash, s.state.Lineage, s.readObject)
	if err != nil || validateRoutedWorkIntentV2(op.Reserve.PlanIntent, plan, s.readObject) != nil || plan.work.Operation != p.OriginCommit || plan.work.Subject != p.Owner || plan.Lease() != p.Lease || !plan.Deadline().Equal(p.Deadline) || plan.work.Transition.Previous != p.Previous || plan.target.Composite.Hash != p.Target {
		return RoutedSelectedPlanV1{}, "", ErrRecovery
	}
	return plan, hash, nil
}

// RoutedPrepareViewV2 is readonly input for physical preparation, never a
// selected transition or proof of actual listener/network state.
type RoutedPrepareViewV2 struct {
	Current, Startup, Saved RoutedActivationBundleV1
	Baseline                *RoutedBaselineV1
}

func (r *RoutedSelectionReaderV2) PrepareView(ctx context.Context, reference SelectionReferenceV2) (RoutedPrepareViewV2, error) {
	var out RoutedPrepareViewV2
	if r == nil || ctx == nil {
		return out, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.read(ctx)
	if err != nil {
		return out, err
	}
	if reference != v.ref {
		return out, ErrConflict
	}
	cfg := v.store.state.Configuration
	out.Current, err = bundleFromConfigurationV2(*cfg)
	if err != nil {
		return out, err
	}
	out.Startup, err = NewRoutedActivationBundleV1(cfg.Firewall.Startup, cfg.LocalServices.Startup)
	if err != nil {
		return out, err
	}
	if active := v.store.state.RoutedActive; active != nil {
		p, e := loadRoutedWorkV2(active.Work, v.store.state.Lineage, v.store.readObject)
		if e != nil {
			return out, e
		}
		out.Baseline = p.Baseline()
	}
	switch {
	case out.Startup.Firewall.Config.SchemaVersion == 4:
		out.Saved = out.Startup
	case out.Current.Firewall.Config.SchemaVersion == 4:
		out.Saved = out.Current
	case out.Baseline != nil:
		out.Saved = out.Baseline.Saved
	default:
		return out, ErrRecovery
	}
	if routedHistoricalWitnessV2(*cfg, out.Saved.Composite.Hash, v.store.readObject) != nil {
		return RoutedPrepareViewV2{}, ErrRecovery
	}
	if err = r.revalidate(ctx, v); err != nil {
		return RoutedPrepareViewV2{}, err
	}
	return out, nil
}

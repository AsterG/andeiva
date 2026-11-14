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

// SelectionReaderPolicyV2 is trusted assembly policy, never request input.
type SelectionReaderPolicyV2 string

const (
	SelectionFullHistoryV2     SelectionReaderPolicyV2 = ""
	SelectionActionAuthorityV2 SelectionReaderPolicyV2 = "action-authority"
)

type SelectionReaderOptionsV2 struct {
	Policy                     SelectionReaderPolicyV2
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
	if (options.Policy != SelectionFullHistoryV2 && options.Policy != SelectionActionAuthorityV2) || area == nil || !validRoutedIdentityV1(options.Identity) || options.Identity.UID == options.Access.OwnerUID || options.Admission == nil || options.Plan == nil || options.Emergency == nil || options.Admission == options.Plan || options.Plan == options.Emergency || options.Admission == options.Emergency || !validReachabilityBudgetV2(options.Budget) || options.Access.CheckDirectory(area) != nil {
		return nil, ErrInvalid
	}
	return &RoutedSelectionReaderV2{area: area, options: options}, nil
}

func (r *RoutedSelectionReaderV2) pools() [3]*recoveryreserve.ReadOnlyPoolV2 {
	return [3]*recoveryreserve.ReadOnlyPoolV2{r.options.Admission, r.options.Plan, r.options.Emergency}
}

func (r *RoutedSelectionReaderV2) read(ctx context.Context) (*selectedViewV2, error) {
	return r.readWithGateV2(ctx, nil)
}

func (r *RoutedSelectionReaderV2) readWithGateV2(ctx context.Context, beforeGraph func(*selectedViewV2) error) (*selectedViewV2, error) {
	view, err := r.readCandidateWithGateV2(ctx, beforeGraph)
	if err != nil {
		return nil, err
	}
	if err := r.revalidate(ctx, view); err != nil {
		_ = view.graph.closeSelectedV2()
		return nil, err
	}
	return view, nil
}

// readCandidateWithGateV2 constructs a private candidate, not authority. A caller
// must revalidate after every dependent read and before returning any proof.
func (r *RoutedSelectionReaderV2) readCandidateWithGateV2(ctx context.Context, beforeGraph func(*selectedViewV2) error) (result *selectedViewV2, resultErr error) {
	if ctx == nil || ctx.Err() != nil || r.area == nil || r.options.Access.CheckDirectory(r.area) != nil {
		return nil, ErrRecovery
	}
	if _, err := r.area.Lstat("selection.pending"); !os.IsNotExist(err) {
		return nil, ErrRecovery
	}
	graph := &v2ReachabilityReader{ctx: ctx, area: r.area, budget: r.options.Budget, objects: map[string]bool{}, edges: map[string]uint8{}, shared: &r.options.Access}
	graph.cache = newSelectedReadCacheV2()
	if r.options.Policy == SelectionActionAuthorityV2 {
		graph.action = &actionReadDependenciesV2{entries: map[string]actionReadDependencyV2{}}
	}
	defer func() {
		if result == nil {
			_ = graph.closeSelectedV2()
		}
	}()
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
	if beforeGraph != nil {
		if err := beforeGraph(view); err != nil {
			return nil, err
		}
	}
	if graph.action != nil {
		s.archiveObserver = func(ref v2ReserveArchiveRef) error {
			return graph.reserveArchiveObject(ref, s.selection.State, s.state, 2)
		}
		if err := graph.actionAuthorityV2(s); err != nil {
			return nil, err
		}
	} else {
		if err := graph.selection(s.selector.Current, &s.selector.Previous); err != nil {
			return nil, err
		}
		if s.selector.Previous != "" {
			if err := graph.selection(s.selector.Previous, nil); err != nil {
				return nil, err
			}
		}
	}
	if manager.verifySelected(s) != nil || validateRoutedActiveV2(s.state, s.readObject) != nil {
		return nil, ErrRecovery
	}
	ref, err := selectedReferenceV2(s)
	if err != nil {
		return nil, err
	}
	view.ref = ref
	return view, nil
}

func (r *RoutedSelectionReaderV2) revalidate(ctx context.Context, v *selectedViewV2) error {
	if ctx.Err() != nil || r.options.Access.CheckDirectory(r.area) != nil {
		return ErrRecovery
	}
	if v.graph.revalidateSelectedV2() != nil {
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

func (r *RoutedSelectionReaderV2) Observe(ctx context.Context) (out SelectionReferenceV2, resultErr error) {
	if r == nil || ctx == nil {
		return SelectionReferenceV2{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.read(ctx)
	if err != nil {
		return SelectionReferenceV2{}, err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			out = SelectionReferenceV2{}
			resultErr = ErrRecovery
		}
	}()
	return v.ref, nil
}

func (r *RoutedSelectionReaderV2) Resolve(ctx context.Context, reference SelectionReferenceV2, purpose RoutedSelectionPurposeV2) (RoutedSelectedPlanV1, error) {
	return r.resolve(ctx, &reference, nil, purpose)
}

// ResolveCurrent derives the complete selected tuple under the reader lock.
// The supplied work reference is only an expectation, never authority.
func (r *RoutedSelectionReaderV2) ResolveCurrent(ctx context.Context, expected RoutedWorkReferenceV1, purpose RoutedSelectionPurposeV2) (RoutedSelectedPlanV1, error) {
	if !validHash(expected.Work) || (expected.Lineage == "" || len(expected.Lineage) > 128) || expected.Generation == 0 {
		return RoutedSelectedPlanV1{}, ErrInvalid
	}
	return r.resolve(ctx, nil, &expected, purpose)
}
func (r *RoutedSelectionReaderV2) resolve(ctx context.Context, expectedSelection *SelectionReferenceV2, expectedWork *RoutedWorkReferenceV1, purpose RoutedSelectionPurposeV2) (out RoutedSelectedPlanV1, resultErr error) {
	if r == nil || ctx == nil {
		return RoutedSelectedPlanV1{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.read(ctx)
	if err != nil {
		return RoutedSelectedPlanV1{}, err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			out = RoutedSelectedPlanV1{}
			resultErr = ErrRecovery
		}
	}()
	if expectedSelection != nil && v.ref != *expectedSelection {
		return RoutedSelectedPlanV1{}, ErrConflict
	}
	reference := v.ref
	if expectedWork != nil && (reference.WorkHash != expectedWork.Work || reference.Lineage != expectedWork.Lineage) {
		return out, ErrConflict
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
	if expectedWork != nil && plan.Reference() != *expectedWork {
		return out, ErrConflict
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
	ServiceRestart          *RoutedServiceRestartViewV3
}

func (r *RoutedSelectionReaderV2) PrepareView(ctx context.Context, reference SelectionReferenceV2) (RoutedPrepareViewV2, error) {
	return r.prepareView(ctx, &reference)
}

// PrepareCurrentView reads and verifies the current preparation view once;
// final selector, pool and object checks remain mandatory.
func (r *RoutedSelectionReaderV2) PrepareCurrentView(ctx context.Context) (RoutedPrepareViewV2, error) {
	return r.prepareView(ctx, nil)
}
func (r *RoutedSelectionReaderV2) prepareView(ctx context.Context, reference *SelectionReferenceV2) (out RoutedPrepareViewV2, resultErr error) {
	if r == nil || ctx == nil {
		return out, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.read(ctx)
	if err != nil {
		return out, err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			out = RoutedPrepareViewV2{}
			resultErr = ErrRecovery
		}
	}()
	if reference != nil && *reference != v.ref {
		return out, ErrConflict
	}
	out, err = routedPrepareViewFromStoreV2(v.store)
	if err != nil {
		return out, err
	}
	if err = addServiceRestartViewV3(v.store, r.options.Identity, &out); err != nil {
		return RoutedPrepareViewV2{}, err
	}
	if err = r.revalidate(ctx, v); err != nil {
		return RoutedPrepareViewV2{}, err
	}
	return out, nil
}

func routedPrepareViewFromStoreV2(store *v2Store) (out RoutedPrepareViewV2, err error) {
	cfg := store.state.Configuration
	if cfg == nil {
		return out, ErrRecovery
	}
	out.Current, err = bundleFromConfigurationV2(*cfg)
	if err != nil {
		return out, err
	}
	out.Startup, err = NewRoutedActivationBundleV1(cfg.Firewall.Startup, cfg.LocalServices.Startup)
	if err != nil {
		return out, err
	}
	if active := store.state.RoutedActive; active != nil {
		p, e := loadRoutedWorkV2(active.Work, store.state.Lineage, store.readObject)
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
	if routedHistoricalWitnessV2(*cfg, out.Saved.Composite.Hash, store.readObject) != nil {
		return RoutedPrepareViewV2{}, ErrRecovery
	}
	return out, nil
}

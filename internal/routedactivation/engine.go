package routedactivation

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localengine"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/nftguardian"
	"github.com/AsterG/andeiva/internal/routednft"
)

type Table uint8

const (
	LegacyTable Table = iota
	RoutedTable
	LocalTable
)

const MaxBatch = 512 << 10

// Kernel is a trusted fixed-namespace capability. Observe must dispatch only the
// three literal table names above, distinguish successful absence from failure,
// and bound every command/output. No public body supplies this implementation.
type Kernel interface {
	Check(context.Context, []byte) error
	Apply(context.Context, []byte) error
	Observe(context.Context, Table) ([]byte, bool, error)
}

// Network is supplied only by trusted assembly, normally *networkexecutor.Executor.
// Typed mementos do not authorize reconstruction or adoption of an existing link.
type Network interface {
	Prepare(context.Context, networkplan.Revision) (networkexecutor.PreparedSnapshot, error)
	VerifyPrepared(context.Context, networkexecutor.PreparedSnapshot) error
	ApplyPrepared(context.Context, networkplan.Revision, networkexecutor.PreparedSnapshot) error
	RestorePrepared(context.Context, networkexecutor.PreparedSnapshot) error
	Verify(context.Context) error
}

type PreparationV1 struct {
	Before       OwnedV1        `json:"before"`
	Target       OwnedV1        `json:"target"`
	Dependencies DependenciesV1 `json:"dependencies"`
}

// ResolvePlan must resolve these exact typed artifacts from selected durable
// intent, preserving lineage, original deadline and owned reservations. It also
// validates contextual object refs; payload shape is never authorization.
type ResolvePlan func(context.Context, configpoc.RoutedTransitionV1, *configpoc.RoutedActivationBundleV1, configpoc.RoutedActivationBundleV1, time.Time) (PreparationV1, error)

type Options struct {
	// These initial revisions are known by trusted supervisor assembly before
	// constructing the helper. New never discovers authority from a table comment.
	Legacy      configpoc.Revision
	Local       *configpoc.Revision
	Neighbors   []localnft.NeighborLink
	ResolvePlan ResolvePlan
}

type Engine struct {
	mu        sync.Mutex
	kernel    Kernel
	network   Network
	listeners localengine.Listeners
	options   Options
	initial   [3]TableStateV1
	selected  bool
	fenced    bool
	plan      configpoc.RoutedTransitionV1
	prepared  PreparationV1
	previous  *configpoc.RoutedActivationBundleV1
	target    configpoc.RoutedActivationBundleV1
	known     [3][]TableStateV1
	preview   *PreparationV1
}

var _ nftguardian.GroupEngine = (*Engine)(nil)

func New(kernel Kernel, network Network, listeners localengine.Listeners, options Options) (*Engine, error) {
	if kernel == nil || network == nil || listeners == nil || options.ResolvePlan == nil {
		return nil, ErrState
	}
	legacy, err := canonicalTable(TableStateV1{Present, &options.Legacy}, 4)
	if err != nil || legacy.Revision.Config.DefaultAction != "deny" || len(legacy.Revision.Config.Rules) != 0 {
		return nil, ErrState
	}
	local := TableStateV1{Presence: Absent}
	if options.Local != nil {
		local, err = canonicalTable(TableStateV1{Present, options.Local}, 3)
		if err != nil || local.Revision.Config.LocalServices == nil || len(local.Revision.Config.LocalServices.Services) != 0 {
			return nil, ErrState
		}
	}
	options.Legacy = *legacy.Revision
	options.Local = local.Revision
	// Neighbor declarations are canonicalized/detached against the target's
	// actual inventory in Prepare before being used by either compiler.
	if len(options.Neighbors) > localnft.MaxInterfaces {
		return nil, ErrState
	}
	for _, link := range options.Neighbors {
		if len(link.Interface) > 15 || len(link.LocalAddresses) > localnft.MaxNeighborAddresses || len(link.PeerAddresses) > localnft.MaxNeighborAddresses {
			return nil, ErrState
		}
		for _, addresses := range [][]string{link.LocalAddresses, link.PeerAddresses} {
			for _, address := range addresses {
				if len(address) > 64 {
					return nil, ErrState
				}
			}
		}
	}
	data, err := json.Marshal(options.Neighbors)
	if err != nil || len(data) > localnft.MaxConfig {
		return nil, ErrState
	}
	if json.Unmarshal(data, &options.Neighbors) != nil {
		return nil, ErrState
	}
	return &Engine{kernel: kernel, network: network, listeners: listeners, options: options,
		initial: [3]TableStateV1{legacy, {Presence: Absent}, local}}, nil
}

func tables(owned OwnedV1) [3]TableStateV1 {
	return [3]TableStateV1{owned.LegacyFirewall, owned.RoutedFirewall, owned.LocalServices}
}

func tableBytes(state TableStateV1) []byte { data, _ := json.Marshal(state); return data }

func (e *Engine) tableMatches(ctx context.Context, table Table, state TableStateV1, deps DependenciesV1) bool {
	data, exists, err := e.kernel.Observe(ctx, table)
	if err != nil || len(data) > 512<<10 || exists != (state.Presence == Present) {
		return false
	}
	if !exists {
		return true
	}
	if state.Revision == nil {
		return false
	}
	switch table {
	case LegacyTable:
		_, err = firewallnft.VerifyObservation(data, *state.Revision)
	case RoutedTable:
		revision, canonicalErr := routednft.Canonical(*state.Revision.Config.Routed)
		if canonicalErr != nil {
			return false
		}
		_, err = routednft.VerifyObservation(data, revision)
	case LocalTable:
		artifact, compileErr := localnft.CompileWithNeighbors(*state.Revision.Config.LocalServices, deps.Neighbors)
		if compileErr != nil {
			return false
		}
		_, err = localnft.VerifyObservation(data, artifact)
	default:
		return false
	}
	return err == nil
}

func (e *Engine) listenersMatch(ctx context.Context, state TableStateV1, deps DependenciesV1) bool {
	actual, err := e.listeners.Observe(ctx)
	if err != nil || len(actual) > localnft.MaxBindings*localnft.MaxServices {
		return false
	}
	// Observe is contractually scoped to this manager's retained namespace and
	// processes. General host listeners are never adopted, enumerated or stopped.
	if state.Presence == Absent {
		return len(actual) == 0
	}
	artifact, err := localnft.CompileWithNeighbors(*state.Revision.Config.LocalServices, deps.Neighbors)
	if err != nil {
		return false
	}
	result, err := localpolicy.Reconcile(artifact.Revision.Config, localpolicy.Observation{Revision: artifact.Revision.Hash, Rules: artifact.Rules, Listeners: actual})
	return err == nil && result.Consistent
}

func (e *Engine) matches(ctx context.Context, owned OwnedV1, deps DependenciesV1) bool {
	if ctx.Err() != nil {
		return false
	}
	if owned.NetworkState == Baseline {
		if e.network.VerifyPrepared(ctx, owned.Network) != nil {
			return false
		}
	} else if e.network.Verify(ctx) != nil {
		return false
	}
	for table, state := range tables(owned) {
		if !e.tableMatches(ctx, Table(table), state, deps) {
			return false
		}
	}
	return e.listenersMatch(ctx, owned.LocalServices, deps)
}

func (e *Engine) Prepare(ctx context.Context, target configpoc.RoutedActivationBundleV1) (PreparationV1, error) {
	if e == nil || ctx == nil {
		return PreparationV1{}, ErrState
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fenced || e.kernel == nil || e.network == nil || e.listeners == nil {
		return PreparationV1{}, ErrState
	}
	bundle, err := configpoc.CanonicalRoutedActivationBundleV1(target)
	if err != nil || bundle.Firewall.Config.SchemaVersion != 6 || bundle.LocalServices.Config.LocalServices == nil {
		return PreparationV1{}, ErrState
	}
	plan := bundle.Firewall.Config.Routed.Network
	var snapshot networkexecutor.PreparedSnapshot
	if e.selected {
		if plan.Hash != e.prepared.Dependencies.Network.Hash || !e.matches(ctx, e.prepared.Target, e.prepared.Dependencies) {
			return PreparationV1{}, ErrState
		}
		snapshot = e.prepared.Dependencies.Prepared
	} else {
		snapshot, err = e.network.Prepare(ctx, plan)
		if err != nil {
			return PreparationV1{}, err
		}
	}
	deps, err := CanonicalDependencies(DependenciesV1{1, plan, snapshot, bundle.LocalServices.Config.LocalServices.Interfaces, e.options.Neighbors})
	if err != nil || localnft.ValidateManaged(*bundle.LocalServices.Config.LocalServices) != nil {
		return PreparationV1{}, ErrState
	}
	before := OwnedV1{1, snapshot, Baseline, e.initial[0], e.initial[1], e.initial[2]}
	if e.selected {
		before = e.prepared.Target
	}
	before, err = CanonicalOwned(before)
	if err != nil || !e.matches(ctx, before, deps) {
		return PreparationV1{}, ErrState
	}
	after, err := CanonicalOwned(OwnedV1{1, snapshot, Configured, TableStateV1{Presence: Absent}, TableStateV1{Present, &bundle.Firewall}, TableStateV1{Present, &bundle.LocalServices}})
	if err != nil {
		return PreparationV1{}, err
	}
	prepared := PreparationV1{before, after, deps}
	deny, err := denyTablesFor(bundle, deps)
	if err != nil {
		return PreparationV1{}, err
	}
	for _, change := range [][2][3]TableStateV1{{tables(before), deny}, {deny, tables(after)}, {deny, tables(before)}} {
		if _, err := e.compileChange(change[0], change[1], deps); err != nil {
			return PreparationV1{}, err
		}
	}
	data, err := json.Marshal(prepared)
	if err != nil {
		return PreparationV1{}, err
	}
	var detached PreparationV1
	if json.Unmarshal(data, &detached) != nil {
		return PreparationV1{}, ErrState
	}
	e.preview = &detached
	return prepared, nil
}

func (e *Engine) ValidatePlan(ctx context.Context, plan configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, target configpoc.RoutedActivationBundleV1, deadline time.Time) error {
	if e == nil || ctx == nil {
		return ErrState
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fenced || !plan.ValidShape() || ctx == nil || ctx.Err() != nil || e.preview == nil {
		return ErrState
	}
	resolved, err := e.options.ResolvePlan(ctx, plan, previous, target, deadline)
	if err != nil {
		return ErrState
	}
	before, err := CanonicalOwned(resolved.Before)
	if err != nil {
		return ErrState
	}
	after, err := CanonicalOwned(resolved.Target)
	if err != nil {
		return ErrState
	}
	deps, err := CanonicalDependencies(resolved.Dependencies)
	if err != nil {
		return ErrState
	}
	canonical := PreparationV1{before, after, deps}
	actual, _ := json.Marshal(canonical)
	want, _ := json.Marshal(e.preview)
	if !bytes.Equal(actual, want) || !e.matches(ctx, before, deps) {
		return ErrState
	}
	if (previous == nil) != (before.NetworkState == Baseline) || (previous != nil && (!e.selected || previous.Composite.Hash != e.target.Composite.Hash)) {
		return ErrState
	}
	if after.RoutedFirewall.Revision == nil || after.RoutedFirewall.Revision.Hash != target.Firewall.Hash || after.LocalServices.Revision == nil || after.LocalServices.Revision.Hash != target.LocalServices.Hash {
		return ErrState
	}
	target, err = configpoc.CanonicalRoutedActivationBundleV1(target)
	if err != nil {
		return ErrState
	}
	if previous != nil {
		detached, err := configpoc.CanonicalRoutedActivationBundleV1(*previous)
		if err != nil {
			return ErrState
		}
		previous = &detached
	}
	e.plan, e.prepared, e.previous, e.target, e.selected = plan, canonical, previous, target, true
	e.known = [3][]TableStateV1{}
	for i, state := range tables(before) {
		e.known[i] = append(e.known[i], state, tables(after)[i])
	}
	return nil
}

func (e *Engine) remember(table int, state TableStateV1) bool {
	for _, known := range e.known[table] {
		if bytes.Equal(tableBytes(known), tableBytes(state)) {
			return true
		}
	}
	// At most before, target and the compiler-derived deny state are owned.
	if len(e.known[table]) >= 3 {
		e.fenced = true
		return false
	}
	e.known[table] = append(e.known[table], state)
	return true
}

func compileTable(table Table, state TableStateV1, exists bool, deps DependenciesV1) ([]byte, error) {
	if state.Presence == Absent {
		if !exists {
			return nil, nil
		}
		name := ""
		switch table {
		case LegacyTable:
			name = firewallnft.TableName
		case RoutedTable:
			name = routednft.TableName
		case LocalTable:
			name = localnft.TableName
		default:
			return nil, ErrState
		}
		return json.Marshal(map[string]any{"nftables": []any{map[string]any{"delete": map[string]any{"table": map[string]any{"family": "inet", "name": name}}}}})
	}
	if state.Revision == nil {
		return nil, ErrState
	}
	var create, replace []byte
	switch table {
	case LegacyTable:
		a, err := firewallnft.Compile(state.Revision.Config)
		if err != nil {
			return nil, err
		}
		create, replace = a.Create, a.Batch
	case RoutedTable:
		a, err := routednft.Compile(*state.Revision.Config.Routed)
		if err != nil {
			return nil, err
		}
		create, replace = a.Create, a.Batch
	case LocalTable:
		a, err := localnft.CompileWithNeighbors(*state.Revision.Config.LocalServices, deps.Neighbors)
		if err != nil {
			return nil, err
		}
		create, replace = a.Create, a.Batch
	default:
		return nil, ErrState
	}
	if exists {
		return replace, nil
	}
	return create, nil
}

func (e *Engine) compileChange(actual, desired [3]TableStateV1, deps DependenciesV1) ([]byte, error) {
	var combined struct {
		Commands []json.RawMessage `json:"nftables"`
	}
	combined.Commands = []json.RawMessage{}
	for table, target := range desired {
		if bytes.Equal(tableBytes(actual[table]), tableBytes(target)) {
			continue
		}
		batch, err := compileTable(Table(table), target, actual[table].Presence == Present, deps)
		if err != nil || len(batch) > MaxBatch {
			return nil, ErrState
		}
		if len(batch) == 0 {
			continue
		}
		var envelope struct {
			Commands []json.RawMessage `json:"nftables"`
		}
		// All bytes originate in the fixed compilers or literal table deletion
		// above. This private merge does not accept JSON from administrative input.
		if json.Unmarshal(batch, &envelope) != nil {
			return nil, ErrState
		}
		combined.Commands = append(combined.Commands, envelope.Commands...)
	}
	data, err := json.Marshal(combined)
	if err != nil || len(data) > MaxBatch {
		return nil, ErrState
	}
	return data, nil
}

func (e *Engine) knownTables(ctx context.Context) ([3]TableStateV1, error) {
	var actual [3]TableStateV1
	for table, candidates := range e.known {
		found := false
		for _, candidate := range candidates {
			if e.tableMatches(ctx, Table(table), candidate, e.prepared.Dependencies) {
				actual[table], found = candidate, true
				break
			}
		}
		if !found {
			e.fenced = true
			return actual, ErrState
		}
	}
	return actual, nil
}

func (e *Engine) applyTables(ctx context.Context, desired [3]TableStateV1) error {
	actual, err := e.knownTables(ctx)
	if err != nil {
		return err
	}
	unchanged := true
	for table, target := range desired {
		if !bytes.Equal(tableBytes(actual[table]), tableBytes(target)) {
			unchanged = false
		}
	}
	if unchanged {
		return ctx.Err()
	}
	batch, err := e.compileChange(actual, desired, e.prepared.Dependencies)
	if err != nil {
		return err
	}
	if e.kernel.Check(ctx, batch) != nil || e.kernel.Apply(ctx, batch) != nil {
		return ErrState
	}
	for table, target := range desired {
		if !e.tableMatches(ctx, Table(table), target, e.prepared.Dependencies) {
			return ErrState
		}
	}
	return ctx.Err()
}

func denyTablesFor(target configpoc.RoutedActivationBundleV1, dependencies DependenciesV1) ([3]TableStateV1, error) {
	policy := *target.Firewall.Config.Routed
	policy.Rules, policy.NAT = []routednft.Rule{}, []routednft.Masquerade{}
	fw, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
	if err != nil {
		return [3]TableStateV1{}, ErrState
	}
	local := localpolicy.Config{SchemaVersion: 1, Interfaces: dependencies.LocalInterfaces, Services: []localpolicy.Service{}}
	localRevision, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &local})
	if err != nil {
		return [3]TableStateV1{}, ErrState
	}
	return [3]TableStateV1{{Presence: Absent}, {Present, &fw}, {Present, &localRevision}}, nil
}

func (e *Engine) Apply(ctx context.Context, target configpoc.RoutedActivationBundleV1) error {
	if e == nil || ctx == nil {
		return ErrState
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	canonical, err := configpoc.CanonicalRoutedActivationBundleV1(target)
	if err != nil || e.fenced || !e.selected || canonical.Composite.Hash != e.target.Composite.Hash || !e.matches(ctx, e.prepared.Before, e.prepared.Dependencies) {
		return ErrState
	}
	deny, err := denyTablesFor(e.target, e.prepared.Dependencies)
	if err != nil {
		return err
	}
	for i, state := range deny {
		if !e.remember(i, state) {
			return ErrState
		}
	}
	// All three table changes are one nft transaction. In particular the real
	// routed drop policy replaces the legacy drop chain before routes can exist.
	if e.applyTables(ctx, deny) != nil {
		return ErrState
	}
	if e.prepared.Before.NetworkState == Baseline {
		if err := e.network.ApplyPrepared(ctx, e.prepared.Dependencies.Network, e.prepared.Dependencies.Prepared); err != nil {
			return err
		}
	} else if e.network.Verify(ctx) != nil {
		return ErrState
	}
	if e.listeners.Apply(ctx, canonical.LocalServices) != nil || !e.listenersMatch(ctx, e.prepared.Target.LocalServices, e.prepared.Dependencies) {
		return ErrState
	}
	if e.applyTables(ctx, tables(e.prepared.Target)) != nil || !e.matches(ctx, e.prepared.Target, e.prepared.Dependencies) {
		return ErrState
	}
	return nil
}

func (e *Engine) observeOwnedLocked(ctx context.Context) (string, error) {
	if ctx == nil || ctx.Err() != nil || e.fenced || e.kernel == nil || e.network == nil || e.listeners == nil {
		return "", ErrState
	}
	if e.selected {
		if e.matches(ctx, e.prepared.Target, e.prepared.Dependencies) {
			return e.plan.TargetOwned, nil
		}
		if e.matches(ctx, e.prepared.Before, e.prepared.Dependencies) {
			return e.plan.BeforeOwned, nil
		}
	} else if e.preview != nil && e.matches(ctx, e.preview.Before, e.preview.Dependencies) {
		data, err := OwnedBytes(e.preview.Before)
		if err == nil {
			return artifactDigest(data), nil
		}
	}
	if e.selected {
		e.fenced = true
	}
	return "", ErrState
}

// MatchOwned checks the exact context-validated artifact reference. Unlike a
// single observed digest, this also handles identical physical before/target
// payloads with distinct contextual object envelopes, without reapplying them.
func (e *Engine) MatchOwned(ctx context.Context, reference string) error {
	if e == nil || ctx == nil {
		return ErrState
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fenced || !e.selected || ctx.Err() != nil {
		return ErrState
	}
	if reference == e.plan.TargetOwned && e.matches(ctx, e.prepared.Target, e.prepared.Dependencies) {
		return nil
	}
	if reference == e.plan.BeforeOwned && e.matches(ctx, e.prepared.Before, e.prepared.Dependencies) {
		return nil
	}
	if reference == e.plan.TargetOwned || reference == e.plan.BeforeOwned {
		_, _ = e.observeOwnedLocked(ctx)
	}
	return ErrState
}

func (e *Engine) ObserveOwned(ctx context.Context) (string, error) {
	if e == nil || ctx == nil {
		return "", ErrState
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.observeOwnedLocked(ctx)
}

func (e *Engine) Current() string {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	owned, err := e.observeOwnedLocked(ctx)
	if err != nil || !e.selected {
		return ""
	}
	if owned == e.plan.TargetOwned {
		return e.target.Composite.Hash
	}
	if owned == e.plan.BeforeOwned && e.previous != nil {
		return e.previous.Composite.Hash
	}
	return ""
}

func (e *Engine) RestoreOwned(ctx context.Context, digest string) error {
	if e == nil || ctx == nil {
		return ErrState
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fenced || !e.selected || digest != e.plan.BeforeOwned || ctx.Err() != nil {
		return ErrState
	}
	deny, err := denyTablesFor(e.target, e.prepared.Dependencies)
	if err != nil {
		return err
	}
	for i, state := range deny {
		if !e.remember(i, state) {
			return ErrState
		}
	}
	if e.applyTables(ctx, deny) != nil {
		e.fenced = true
		return ErrState
	}
	local := e.prepared.Before.LocalServices.Revision
	if local == nil {
		local = deny[2].Revision
	}
	if e.listeners.Apply(ctx, *local) != nil || !e.listenersMatch(ctx, e.prepared.Before.LocalServices, e.prepared.Dependencies) {
		e.fenced = true
		return ErrState
	}
	if e.prepared.Before.NetworkState == Baseline {
		if err := e.network.RestorePrepared(ctx, e.prepared.Dependencies.Prepared); err != nil {
			e.fenced = true
			return err
		}
	} else if e.network.Verify(ctx) != nil {
		e.fenced = true
		return ErrState
	}
	if e.applyTables(ctx, tables(e.prepared.Before)) != nil || !e.matches(ctx, e.prepared.Before, e.prepared.Dependencies) {
		e.fenced = true
		return ErrState
	}
	return nil
}

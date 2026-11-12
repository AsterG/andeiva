package routedactivation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/nftguardian"
	"github.com/AsterG/andeiva/internal/routednft"
)

type kernelFixture struct {
	objects        map[Table][]map[string]any
	batches        [][]byte
	failAt, lostAt int
	readFail       bool
}

func (k *kernelFixture) Check(ctx context.Context, data []byte) error {
	if ctx.Err() != nil || len(data) > MaxBatch {
		return ErrState
	}
	return nil
}
func tableID(name string) (Table, bool) {
	switch name {
	case firewallnft.TableName:
		return LegacyTable, true
	case routednft.TableName:
		return RoutedTable, true
	case localnft.TableName:
		return LocalTable, true
	}
	return 0, false
}
func (k *kernelFixture) Apply(ctx context.Context, data []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	k.batches = append(k.batches, append([]byte{}, data...))
	call := len(k.batches)
	if k.failAt == call {
		return ErrState
	}
	var envelope struct {
		Commands []map[string]map[string]map[string]any `json:"nftables"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return ErrState
	}
	for _, command := range envelope.Commands {
		for verb, objects := range command {
			for kind, body := range objects {
				name, _ := body["table"].(string)
				if kind == "table" {
					name, _ = body["name"].(string)
				}
				table, ok := tableID(name)
				if !ok {
					return ErrState
				}
				if verb == "delete" && kind == "table" {
					delete(k.objects, table)
					continue
				}
				if verb != "add" {
					return ErrState
				}
				if kind == "rule" {
					for _, raw := range body["expr"].([]any) {
						expr := raw.(map[string]any)
						if _, ok := expr["counter"]; ok {
							expr["counter"] = map[string]any{"packets": 0, "bytes": 0}
						}
					}
				}
				k.objects[table] = append(k.objects[table], map[string]any{kind: body})
			}
		}
	}
	if k.lostAt == call {
		return ErrState
	}
	return nil
}
func (k *kernelFixture) Observe(ctx context.Context, table Table) ([]byte, bool, error) {
	if k.readFail || ctx.Err() != nil {
		return nil, false, ErrState
	}
	objects, exists := k.objects[table]
	data, err := json.Marshal(map[string]any{"nftables": objects})
	return data, exists, err
}

type networkFixture struct {
	snapshot networkexecutor.PreparedSnapshot
	active   bool
	calls    int
	before   func() error
	cancel   context.CancelFunc
}

func (n *networkFixture) Prepare(ctx context.Context, plan networkplan.Revision) (networkexecutor.PreparedSnapshot, error) {
	if n.active || ctx.Err() != nil || plan.Hash != n.snapshot.PlanHash {
		return networkexecutor.PreparedSnapshot{}, ErrState
	}
	return networkexecutor.CanonicalPreparedSnapshot(n.snapshot)
}
func (n *networkFixture) VerifyPrepared(ctx context.Context, snapshot networkexecutor.PreparedSnapshot) error {
	a, err := networkexecutor.PreparedSnapshotBytes(n.snapshot)
	b, other := networkexecutor.PreparedSnapshotBytes(snapshot)
	if ctx.Err() != nil || n.active || err != nil || other != nil || !bytes.Equal(a, b) {
		return ErrState
	}
	return nil
}
func (n *networkFixture) Verify(ctx context.Context) error {
	if !n.active || ctx.Err() != nil {
		return ErrState
	}
	return nil
}
func (n *networkFixture) ApplyPrepared(ctx context.Context, plan networkplan.Revision, snapshot networkexecutor.PreparedSnapshot) error {
	if n.VerifyPrepared(ctx, snapshot) != nil || plan.Hash != snapshot.PlanHash {
		return ErrState
	}
	if n.before != nil && n.before() != nil {
		return ErrState
	}
	n.calls++
	n.active = true
	if n.cancel != nil {
		n.cancel()
	}
	return ctx.Err()
}
func (n *networkFixture) RestorePrepared(ctx context.Context, snapshot networkexecutor.PreparedSnapshot) error {
	if ctx.Err() != nil || n.snapshot.Hash != snapshot.Hash {
		return ErrState
	}
	n.active = false
	return nil
}

type listenersFixture struct {
	actual   []localpolicy.Listener
	failOnce bool
	calls    int
}

func (l *listenersFixture) Apply(ctx context.Context, revision configpoc.Revision) error {
	l.calls++
	if ctx.Err() != nil {
		return ctx.Err()
	}
	l.actual = nil
	for _, service := range revision.Config.LocalServices.Services {
		if service.Enabled {
			for _, binding := range service.Bindings {
				l.actual = append(l.actual, localpolicy.Listener{Owner: service.Owner, Service: service.ID, Interface: binding.Interface, LocalAddress: binding.LocalAddress, Protocol: service.Endpoints[0].Protocol, Port: service.Endpoints[0].FirstPort})
			}
		}
	}
	if l.failOnce {
		l.failOnce = false
		return ErrState
	}
	return nil
}
func (l *listenersFixture) Observe(ctx context.Context) ([]localpolicy.Listener, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return append([]localpolicy.Listener{}, l.actual...), nil
}

type assembledFixture struct {
	engine    *Engine
	group     *nftguardian.Group
	kernel    *kernelFixture
	network   *networkFixture
	listeners *listenersFixture
	target    configpoc.RoutedActivationBundleV1
	prepared  PreparationV1
	plan      configpoc.RoutedTransitionV1
	started   time.Time
}

func assembleFixture(t testing.TB) assembledFixture {
	t.Helper()
	before, deps, target := artifactFixture(t)
	kernel := &kernelFixture{objects: map[Table][]map[string]any{}}
	batch, err := compileTable(LegacyTable, before.LegacyFirewall, false, deps)
	if err != nil || kernel.Apply(context.Background(), batch) != nil {
		t.Fatal("establish actual default deny", err)
	}
	kernel.batches = nil
	network := &networkFixture{snapshot: before.Network}
	listeners := &listenersFixture{}
	started := time.Now().UTC()
	plan := configpoc.RoutedTransitionV1{Version: 1, Operation: "fixture", Previous: strings.Repeat("1", 64), Target: strings.Repeat("2", 64), BeforeOwned: strings.Repeat("3", 64), TargetOwned: strings.Repeat("4", 64), Dependencies: strings.Repeat("5", 64)}
	var prepared PreparationV1
	engine, err := New(kernel, network, listeners, Options{Legacy: *before.LegacyFirewall.Revision,
		ResolvePlan: func(ctx context.Context, actual configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, actualTarget configpoc.RoutedActivationBundleV1, deadline time.Time) (PreparationV1, error) {
			if ctx.Err() != nil || actual != plan || previous != nil || actualTarget.Composite.Hash != target.Composite.Hash || !deadline.Equal(started.Add(10*time.Second)) {
				return PreparationV1{}, ErrState
			}
			return prepared, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = engine.Prepare(context.Background(), target)
	if err != nil {
		t.Fatal("physical prepare", err)
	}
	group, err := nftguardian.NewGroup(engine)
	if err != nil {
		t.Fatal(err)
	}
	network.before = func() error {
		deny, err := denyTablesFor(target, prepared.Dependencies)
		if err != nil {
			return err
		}
		for table, state := range deny {
			if !engine.tableMatches(context.Background(), Table(table), state, prepared.Dependencies) {
				return errors.New("L3 effects attempted without real deny readback")
			}
		}
		return nil
	}
	return assembledFixture{engine, group, kernel, network, listeners, target, prepared, plan, started}
}

func TestGroupEngineDenyFirstAtomicHandoverAndExactRestore(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	if err := f.group.BootstrapStartup(context.Background(), f.plan, f.target, f.started); err != nil {
		t.Fatal("bootstrap", err)
	}
	state, hash, err := f.group.SnapshotObserved()
	if err != nil || state.Phase != "pending" || hash != f.target.Composite.Hash || f.network.calls != 1 || len(f.kernel.batches) != 2 || len(f.listeners.actual) != 1 {
		t.Fatal("unverified target", state, hash, err)
	}
	if _, exists := f.kernel.objects[LegacyTable]; exists {
		t.Fatal("old drop residual")
	}
	first := string(f.kernel.batches[0])
	if !strings.Contains(first, `"delete":{"table":{"family":"inet","name":"andeiva_admin"}}`) || !strings.Contains(first, "andeiva_routed") || !strings.Contains(first, "andeiva_local") {
		t.Fatal("handover was split instead of one transaction")
	}
	if err := f.group.RecoverLease(f.plan, state); err != nil {
		t.Fatal("restore", err)
	}
	if f.network.active || len(f.listeners.actual) != 0 || f.engine.Current() != "" || !f.engine.matches(context.Background(), f.prepared.Before, f.prepared.Dependencies) {
		t.Fatal("physical before was not restored")
	}
}

func TestGroupEngineFaultsRestoreWithoutCallerContext(t *testing.T) {
	for _, fault := range []string{"deny-lost-ack", "target-failed", "listener-partial", "caller-canceled"} {
		t.Run(fault, func(t *testing.T) {
			f := assembleFixture(t)
			defer f.group.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "deny-lost-ack":
				f.kernel.lostAt = 1
			case "target-failed":
				f.kernel.failAt = 2
			case "listener-partial":
				f.listeners.failOnce = true
			case "caller-canceled":
				f.network.cancel = cancel
			}
			if err := f.group.BootstrapStartup(ctx, f.plan, f.target, f.started); err == nil {
				t.Fatal("fault claimed success")
			}
			if f.network.active || len(f.listeners.actual) != 0 || !f.engine.matches(context.Background(), f.prepared.Before, f.prepared.Dependencies) {
				t.Fatal("compensation did not restore exact before")
			}
		})
	}
}

func TestGroupEngineRejectsForeignTablesAndScopes(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	f.kernel.objects[LocalTable] = []map[string]any{{"table": map[string]any{"family": "inet", "name": "andeiva_local", "comment": "foreign"}}}
	if _, err := f.engine.Prepare(context.Background(), f.target); err == nil || len(f.kernel.batches) != 0 || f.network.calls != 0 {
		t.Fatal("foreign table adopted")
	}
	f = assembleFixture(t)
	defer f.group.Close()
	wrong := f.plan
	wrong.Dependencies = strings.Repeat("f", 64)
	if err := f.group.BootstrapStartup(context.Background(), wrong, f.target, f.started); err == nil || len(f.kernel.batches) != 0 || f.network.calls != 0 {
		t.Fatal("wrong selected artifact scope admitted")
	}
	f = assembleFixture(t)
	defer f.group.Close()
	f.kernel.readFail = true
	if _, err := f.engine.Prepare(context.Background(), f.target); err == nil || len(f.kernel.batches) != 0 || f.network.calls != 0 {
		t.Fatal("failed table query was interpreted as absence")
	}
}

func TestGroupEngineReadbackUncertaintyFencesAndConfirmUsesPhysicalState(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	if err := f.group.BootstrapStartup(context.Background(), f.plan, f.target, f.started); err != nil {
		t.Fatal(err)
	}
	state, _, err := f.group.SnapshotObserved()
	if err != nil {
		t.Fatal(err)
	}
	// A syntactically valid, complete but different routed policy cannot be
	// accepted from its comment or the engine's last successful target hash.
	policy := *f.target.Firewall.Config.Routed
	policy.Rules, policy.NAT = []routednft.Rule{}, []routednft.Masquerade{}
	artifact, err := routednft.Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	delete(f.kernel.objects, RoutedTable)
	if f.kernel.Apply(context.Background(), artifact.Create) != nil {
		t.Fatal("replace fixture policy")
	}
	if f.group.ConfirmLease(context.Background(), f.plan, state) == nil || f.engine.Current() != "" {
		t.Fatal("cached target confirmed drift")
	}
	calls := len(f.kernel.batches)
	if f.group.RecoverLease(f.plan, state) == nil || len(f.kernel.batches) != calls {
		t.Fatal("uncertain state blindly overwritten")
	}
}

func TestGroupEngineSameContentDistinctContextRefsStillOwnOneLease(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	ctx := context.Background()
	if err := f.group.BootstrapStartup(ctx, f.plan, f.target, f.started); err != nil {
		t.Fatal(err)
	}
	state, _, err := f.group.SnapshotObserved()
	if err != nil || f.group.ConfirmLease(ctx, f.plan, state) != nil {
		t.Fatal("confirm bootstrap", err)
	}
	prepared, err := f.engine.Prepare(ctx, f.target)
	if err != nil {
		t.Fatal(err)
	}
	plan := f.plan
	plan.Operation = "same-content"
	plan.BeforeOwned, plan.TargetOwned = strings.Repeat("6", 64), strings.Repeat("7", 64)
	deadline := time.Now().UTC().Add(30 * time.Second)
	f.engine.options.ResolvePlan = func(ctx context.Context, actual configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, target configpoc.RoutedActivationBundleV1, actualDeadline time.Time) (PreparationV1, error) {
		if ctx.Err() != nil || actual != plan || previous == nil || previous.Composite.Hash != f.target.Composite.Hash || target.Composite.Hash != f.target.Composite.Hash || !actualDeadline.Equal(deadline) {
			return PreparationV1{}, ErrState
		}
		return prepared, nil
	}
	if err := f.group.ArmUntil(ctx, plan, f.target, f.target, deadline); err != nil {
		t.Fatal("arm equal payload with distinct selected envelopes", err)
	}
	state, _, err = f.group.SnapshotObserved()
	if err != nil {
		t.Fatal(err)
	}
	batches, calls := len(f.kernel.batches), f.listeners.calls
	if f.group.ApplyLease(ctx, plan, f.target, state) != nil || f.group.ConfirmLease(ctx, plan, state) != nil || len(f.kernel.batches) != batches || f.listeners.calls != calls || f.network.calls != 1 {
		t.Fatal("same content lost receipt or reapplied effects")
	}
}

func TestGroupEngineConfirmRecoverSerializePhysicalOutcome(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	if err := f.group.BootstrapStartup(context.Background(), f.plan, f.target, f.started); err != nil {
		t.Fatal(err)
	}
	state, _, err := f.group.SnapshotObserved()
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() { <-start; results <- f.group.ConfirmLease(context.Background(), f.plan, state) }()
	go func() { <-start; results <- f.group.RecoverLease(f.plan, state) }()
	close(start)
	a, b := <-results, <-results
	if (a == nil) == (b == nil) {
		t.Fatal("more or fewer than one authority won", a, b)
	}
	if _, _, err := f.group.SnapshotObserved(); err != nil {
		t.Fatal("physical outcome not verified", err)
	}
}

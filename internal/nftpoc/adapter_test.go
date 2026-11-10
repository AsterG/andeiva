package nftpoc

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

type memoryTransport struct {
	mu                  sync.Mutex
	state               []byte
	checkFailure        bool
	applyFailure        bool
	responseLost        bool
	observeFailure      bool
	loseReadback        bool
	observationFailures int
	checks, writes      int
}

func (m *memoryTransport) Check(ctx context.Context, _ []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checks++
	if m.checkFailure {
		return ErrTransport
	}
	return ctx.Err()
}
func (m *memoryTransport) Apply(ctx context.Context, batch []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.applyFailure {
		return ErrTransport
	}
	var envelope struct{ Nftables []map[string]json.RawMessage }
	if err := json.Unmarshal(batch, &envelope); err != nil {
		return err
	}
	objects := []json.RawMessage{}
	for _, command := range envelope.Nftables {
		if entry, ok := command["add"]; ok {
			objects = append(objects, entry)
		}
	}
	m.state, _ = json.Marshal(map[string]any{"nftables": objects})
	m.writes++
	if m.loseReadback {
		m.loseReadback = false
		m.observationFailures++
	}
	if m.responseLost {
		m.responseLost = false
		return ErrTransport
	}
	return nil
}
func (m *memoryTransport) Observe(ctx context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.observationFailures > 0 {
		m.observationFailures--
		return nil, ErrTransport
	}
	if m.observeFailure {
		return nil, ErrTransport
	}
	return append([]byte{}, m.state...), ctx.Err()
}

func TestAdapterChecksAndObservesEveryTransition(t *testing.T) {
	transport := &memoryTransport{state: observation(t, DefaultConfig())}
	engine := New(transport)
	baseline, _ := Compile(DefaultConfig())
	target, _ := Compile(FixtureConfig(true, false, false, false))
	if engine.Current() != baseline.Revision.Hash || engine.Validate(target.Revision.Config) != nil || engine.Apply(context.Background(), target.Revision) != nil || engine.Current() != target.Revision.Hash {
		t.Fatal("valid transition failed")
	}
	if transport.checks != 2 || transport.writes != 1 {
		t.Fatal("check/apply sequence not enforced")
	}
	if err := engine.Apply(context.Background(), baseline.Revision); err != nil || engine.Current() != baseline.Revision.Hash {
		t.Fatal("rollback failed")
	}
	transport.checkFailure = true
	if engine.Apply(context.Background(), target.Revision) == nil || engine.Current() != baseline.Revision.Hash {
		t.Fatal("failed validation changed state")
	}
	transport.checkFailure = false
	transport.responseLost = true
	if engine.Apply(context.Background(), target.Revision) == nil || engine.Current() != target.Revision.Hash {
		t.Fatal("lost acknowledgment not observed")
	}
	if engine.Apply(context.Background(), baseline.Revision) != nil {
		t.Fatal("lost acknowledgment compensation failed")
	}
	transport.state = observation(t, FixtureConfig(false, true, false, false))
	if engine.Current() != "" || !errors.Is(engine.Apply(context.Background(), target.Revision), ErrDrift) {
		t.Fatal("foreign revision accepted")
	}
}

func TestAdapterReconcilesIndependentRollback(t *testing.T) {
	baseline, _ := Compile(DefaultConfig())
	target, _ := Compile(FixtureConfig(true, true, false, false))
	transport := &memoryTransport{state: observation(t, DefaultConfig())}
	engine := New(transport)
	if engine.Apply(context.Background(), target.Revision) != nil {
		t.Fatal("apply failed")
	}
	transport.state = observation(t, DefaultConfig())
	if engine.Current() != "" {
		t.Fatal("independent change not detected")
	}
	if engine.Apply(context.Background(), baseline.Revision) != nil || engine.Current() != baseline.Revision.Hash || transport.writes != 1 {
		t.Fatal("verified no-op reconciliation failed")
	}
}

func TestAdapterCompensatesUnknownDispatchOutcome(t *testing.T) {
	baseline, _ := Compile(DefaultConfig())
	target, _ := Compile(FixtureConfig(true, true, false, false))
	third, _ := Compile(FixtureConfig(false, false, true, true))
	transport := &memoryTransport{state: observation(t, DefaultConfig()), loseReadback: true}
	engine := New(transport)
	if engine.Apply(context.Background(), target.Revision) == nil {
		t.Fatal("lost readback reported success")
	}
	if !errors.Is(engine.Apply(context.Background(), third.Revision), ErrDrift) {
		t.Fatal("unrelated transition accepted while outcome uncertain")
	}
	if engine.Apply(context.Background(), baseline.Revision) != nil || engine.Current() != baseline.Revision.Hash {
		t.Fatal("known own transition could not be compensated")
	}
	transport.loseReadback = true
	if engine.Apply(context.Background(), target.Revision) == nil {
		t.Fatal("second readback loss reported success")
	}
	transport.state = observation(t, third.Revision.Config)
	if engine.Current() != "" || !errors.Is(engine.Apply(context.Background(), baseline.Revision), ErrDrift) {
		t.Fatal("unknown third revision accepted during reconciliation")
	}
}

func TestAdapterRejectsMalformedRevisionAndUnavailableTransport(t *testing.T) {
	artifact, _ := Compile(DefaultConfig())
	artifact.Revision.Hash = "untrusted"
	if !errors.Is(New(nil).Apply(context.Background(), artifact.Revision), ErrPolicy) || New(nil).Current() != "" || New(nil).Validate(DefaultConfig()) == nil {
		t.Fatal("unsafe boundary accepted")
	}
	transport := &memoryTransport{state: []byte(`{"nftables":[]}`)}
	valid, _ := Compile(FixtureConfig(true, false, false, false))
	if New(transport).Apply(context.Background(), valid.Revision) == nil || transport.writes != 0 {
		t.Fatal("unregistered table changed")
	}
}

func TestAdapterConcurrentAccess(t *testing.T) {
	transport := &memoryTransport{state: observation(t, DefaultConfig())}
	engine := New(transport)
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			artifact, _ := Compile(FixtureConfig(i%2 == 0, i%2 != 0, false, false))
			if err := engine.Apply(context.Background(), artifact.Revision); err != nil {
				t.Errorf("apply: %v", err)
			}
			if engine.Current() == "" {
				t.Error("inconsistent readback")
			}
		}(i)
	}
	group.Wait()
	if _, err := DecodeObservation(transport.state); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterImplementsTransactionContract(t *testing.T) {
	var engine configpoc.Engine = New(nil)
	if engine.Name() != "nft-fixture-v1" {
		t.Fatal("unstable engine name")
	}
}

func TestAdapterTransactionStatesAndRecovery(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the journal implementation requires Linux")
	}
	// Exercise lease expiry without charging filesystem or race-detector latency
	// against the simulated transport's confirmation window.
	synctest.Test(t, testAdapterTransactionStatesAndRecovery)
}

func testAdapterTransactionStatesAndRecovery(t *testing.T) {
	transport := &memoryTransport{state: observation(t, DefaultConfig())}
	dir := filepath.Join(t.TempDir(), "state")
	service, err := configpoc.Open(dir, []configpoc.Engine{New(transport)}, configpoc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close() }()
	principal := configpoc.Principal{ID: "lab-admin", Role: configpoc.RoleAdmin}
	status := func() configpoc.Snapshot {
		t.Helper()
		state, err := service.Execute(context.Background(), principal, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
		if err != nil || state.RecoveryRequired {
			t.Fatalf("status: %v, recovery=%v", err, state.RecoveryRequired)
		}
		return state
	}
	execute := func(request configpoc.Request) configpoc.Snapshot {
		t.Helper()
		request.ExpectedGeneration = status().Generation
		state, err := service.Execute(context.Background(), principal, configpoc.CLI, request)
		if err != nil {
			t.Fatalf("%s: %v", request.Operation, err)
		}
		return state
	}
	initial := status()
	policyA := FixtureConfig(true, false, false, false)
	policyB := FixtureConfig(false, true, false, false)
	a, _ := Compile(policyA)
	b, _ := Compile(policyB)
	state := execute(configpoc.Request{Operation: configpoc.OpStage, Key: "stage-a", Config: &policyA})
	if state.Running.Hash != initial.Running.Hash || state.Startup.Hash != initial.Startup.Hash || state.Candidate.Revision.Hash != a.Revision.Hash {
		t.Fatal("candidate leaked into active states")
	}
	state = execute(configpoc.Request{Operation: configpoc.OpCommit, Key: "commit-a"})
	if state.Running.Hash != a.Revision.Hash || state.Startup.Hash != initial.Startup.Hash {
		t.Fatal("commit changed Startup")
	}
	execute(configpoc.Request{Operation: configpoc.OpSave, Key: "save-a"})
	execute(configpoc.Request{Operation: configpoc.OpStage, Key: "stage-b", Config: &policyB})
	state = execute(configpoc.Request{Operation: configpoc.OpCommit, Key: "provisional-b", ConfirmFor: 150 * time.Millisecond})
	if state.Pending == nil || state.Running.Hash != b.Revision.Hash {
		t.Fatal("provisional commit not active")
	}
	time.Sleep(time.Until(state.Pending.Deadline) - time.Millisecond)
	synctest.Wait()
	if state = status(); state.Pending == nil || state.Running.Hash != b.Revision.Hash {
		t.Fatal("provisional revision expired before its deadline")
	}
	time.Sleep(time.Millisecond)
	synctest.Wait()
	state = status()
	if state.Pending != nil || state.Running.Hash != a.Revision.Hash || state.Startup.Hash != a.Revision.Hash {
		t.Fatal("expiry did not restore observed revision")
	}
	execute(configpoc.Request{Operation: configpoc.OpStage, Key: "stage-b-again", Config: &policyB})
	execute(configpoc.Request{Operation: configpoc.OpCommit, Key: "provisional-b-again", ConfirmFor: time.Second})
	execute(configpoc.Request{Operation: configpoc.OpConfirm, Key: "confirm-b", Target: b.Revision.Hash})
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	service, err = configpoc.Open(dir, []configpoc.Engine{New(transport)}, configpoc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	state = status()
	if state.Running.Hash != b.Revision.Hash || state.Startup.Hash != a.Revision.Hash {
		t.Fatal("controller reopen lost Running/Startup separation")
	}
	execute(configpoc.Request{Operation: configpoc.OpStage, Key: "stage-failure", Config: &policyA})
	transport.applyFailure = true
	_, err = service.Execute(context.Background(), principal, configpoc.Web, configpoc.Request{Operation: configpoc.OpCommit, Key: "failed-apply", ExpectedGeneration: status().Generation})
	if !errors.Is(err, configpoc.ErrEngine) || status().Running.Hash != b.Revision.Hash {
		t.Fatalf("failed apply was not compensated: %v", err)
	}
	history, err := service.History(principal)
	if err != nil {
		t.Fatal(err)
	}
	foundCompensation, foundExpiry := false, false
	for _, event := range history {
		foundCompensation = foundCompensation || event.Result == "compensated"
		foundExpiry = foundExpiry || event.Operation == "timeout"
	}
	if !foundCompensation || !foundExpiry {
		t.Fatal("recovery audit missing")
	}
}

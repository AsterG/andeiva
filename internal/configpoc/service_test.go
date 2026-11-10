package configpoc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

var admin = Principal{ID: "alice", Role: RoleAdmin}

func fixture(t *testing.T, options Options) (*Service, []*SimEngine, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("file durability experiment requires Linux")
	}
	dir := filepath.Join(t.TempDir(), "state")
	engines := []*SimEngine{NewSimEngine("first"), NewSimEngine("second")}
	s, err := Open(dir, []Engine{engines[0], engines[1]}, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, engines, dir
}
func status(t *testing.T, s *Service) Snapshot {
	t.Helper()
	r, err := s.Execute(context.Background(), admin, API, Request{Operation: OpStatus})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func invoke(t *testing.T, s *Service, operation string, config *Config, ttl time.Duration) Snapshot {
	t.Helper()
	before := status(t, s)
	r, err := s.Execute(context.Background(), admin, API, Request{Operation: operation, Key: fmt.Sprintf("request-%d-%s", before.Generation, operation), ExpectedGeneration: before.Generation, Config: config, ConfirmFor: ttl})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func sample(id string) Config {
	return Config{SchemaVersion: 1, DefaultAction: "deny", Rules: []Rule{{ID: id, Action: "allow"}}}
}

func TestCanonicalAndIsolation(t *testing.T) {
	a, _ := Canonical(Config{SchemaVersion: 1, DefaultAction: "deny"})
	b, _ := Canonical(Config{SchemaVersion: 1, DefaultAction: "deny", Rules: []Rule{}})
	if a.Hash != b.Hash {
		t.Fatal("nil and empty rules differ")
	}
	c := sample("one")
	c.Rules = append(c.Rules, Rule{ID: "two", Action: "deny"})
	a, _ = Canonical(c)
	c.Rules[0], c.Rules[1] = c.Rules[1], c.Rules[0]
	b, _ = Canonical(c)
	if a.Hash == b.Hash {
		t.Fatal("rule order lost")
	}
	for _, bad := range []Config{{SchemaVersion: 3, DefaultAction: "deny"}, {SchemaVersion: 1, DefaultAction: "allow"}, {SchemaVersion: 1, DefaultAction: "deny", Rules: []Rule{{ID: "one", Action: "allow"}, {ID: "one", Action: "deny"}}}, {SchemaVersion: 1, DefaultAction: "deny", Rules: []Rule{{ID: "../x", Action: "allow"}}}} {
		if _, err := Canonical(bad); !errors.Is(err, ErrInvalid) {
			t.Fatal("accepted invalid config")
		}
	}
	s, _, _ := fixture(t, Options{})
	original := sample("safe")
	out := invoke(t, s, OpStage, &original, 0)
	hash := out.Candidate.Revision.Hash
	original.Rules[0].Action = "deny"
	out.Candidate.Revision.Config.Rules[0].Action = "deny"
	if now := status(t, s); now.Candidate.Revision.Hash != hash || now.Candidate.Revision.Config.Rules[0].Action != "allow" {
		t.Fatal("mutable alias")
	}
}

func TestStatesReplayAndPersistence(t *testing.T) {
	s, engines, dir := fixture(t, Options{})
	initial := status(t, s)
	c := sample("one")
	invoke(t, s, OpStage, &c, 0)
	invoke(t, s, OpValidate, nil, 0)
	before := status(t, s)
	req := Request{Operation: OpCommit, Key: "commit-key", ExpectedGeneration: before.Generation}
	a, err := s.Execute(context.Background(), admin, CLI, req)
	if err != nil {
		t.Fatal(err)
	}
	if a.Running.Hash == initial.Running.Hash || a.Startup.Hash != initial.Startup.Hash || a.Pending != nil {
		t.Fatal("states conflated")
	}
	replayed, err := s.Execute(context.Background(), admin, Web, req)
	if err != nil || replayed.ReplayedGeneration != a.Generation {
		t.Fatalf("replay: %v", err)
	}
	req.Target = "different"
	if _, err = s.Execute(context.Background(), admin, API, req); !errors.Is(err, ErrReplay) {
		t.Fatal("key payload not bound")
	}
	_ = s.Close()
	s, err = Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if status(t, s).Running.Hash != a.Running.Hash {
		t.Fatal("controller restart lost running")
	}
	_ = s.Close()
	s, err = Open(dir, []Engine{engines[0], engines[1]}, Options{Boot: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if status(t, s).Running.Hash != initial.Startup.Hash {
		t.Fatal("boot did not load startup")
	}
	c = sample("saved")
	invoke(t, s, OpStage, &c, 0)
	want := invoke(t, s, OpCommit, nil, 0)
	invoke(t, s, OpSave, nil, 0)
	_ = s.Close()
	s, err = Open(dir, []Engine{engines[0], engines[1]}, Options{Boot: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if status(t, s).Running.Hash != want.Running.Hash {
		t.Fatal("save lost")
	}
}

func TestConfirmedTimeoutAndRestart(t *testing.T) {
	for _, mode := range []string{"timer", "restart", "confirm"} {
		t.Run(mode, func(t *testing.T) {
			s, engines, dir := fixture(t, Options{})
			previous := status(t, s).Running.Hash
			c := sample("temporary")
			invoke(t, s, OpStage, &c, 0)
			pending := invoke(t, s, OpCommit, nil, 150*time.Millisecond)
			_, err := s.Execute(context.Background(), admin, API, Request{Operation: OpSave, Key: "save-pending", ExpectedGeneration: pending.Generation})
			if !errors.Is(err, ErrPending) {
				t.Fatal("save allowed pending")
			}
			switch mode {
			case "timer":
				time.Sleep(250 * time.Millisecond)
				if status(t, s).Running.Hash != previous {
					t.Fatal("timeout did not revert")
				}
			case "restart":
				_ = s.Close()
				s, err = Open(dir, []Engine{engines[0], engines[1]}, Options{})
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				if status(t, s).Running.Hash != previous {
					t.Fatal("restart did not revert")
				}
			case "confirm":
				result, err := s.Execute(context.Background(), admin, API, Request{Operation: OpConfirm, Key: "confirm", ExpectedGeneration: pending.Generation, Target: pending.Running.Hash})
				if err != nil || result.Pending != nil {
					t.Fatalf("confirm %v", err)
				}
				time.Sleep(200 * time.Millisecond)
				if status(t, s).Running.Hash != pending.Running.Hash {
					t.Fatal("confirmed rolled back")
				}
			}
		})
	}
}

func TestPartialApplyCompensationAndDrift(t *testing.T) {
	s, engines, _ := fixture(t, Options{})
	previous := status(t, s).Running.Hash
	c := sample("new")
	invoke(t, s, OpStage, &c, 0)
	before := status(t, s)
	engines[1].FailNext("after")
	_, err := s.Execute(context.Background(), admin, API, Request{Operation: OpCommit, Key: "fail", ExpectedGeneration: before.Generation})
	if !errors.Is(err, ErrEngine) {
		t.Fatal(err)
	}
	for _, e := range engines {
		if e.Current() != previous {
			t.Fatal("failed engine not compensated")
		}
	}
	engines[0].Drift("foreign")
	if !status(t, s).RecoveryRequired {
		t.Fatal("drift not observed")
	}
	before = status(t, s)
	_, err = s.Execute(context.Background(), admin, API, Request{Operation: OpSave, Key: "drift-save", ExpectedGeneration: before.Generation})
	if !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	invoke(t, s, OpRecover, nil, 0)
	if status(t, s).RecoveryRequired {
		t.Fatal("recovery did not clear")
	}
}

func TestTimeoutFailureNeverPromotesTemporary(t *testing.T) {
	s, engines, dir := fixture(t, Options{})
	previous := status(t, s).Running.Hash
	c := sample("temporary")
	invoke(t, s, OpStage, &c, 0)
	pending := invoke(t, s, OpCommit, nil, time.Second)
	engines[1].SetFailure(previous, "before")
	s.mu.Lock()
	err := s.expire()
	s.mu.Unlock()
	if !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	state := status(t, s)
	if !state.RecoveryRequired || state.Pending == nil || state.LastGood.Hash == pending.Running.Hash {
		t.Fatal("temporary state promoted")
	}
	history, err := s.History(admin)
	if err != nil || history[len(history)-1].Result != "compensation_failed" {
		t.Fatal("audit misreported failed compensation")
	}
	_, err = s.Execute(context.Background(), admin, API, Request{Operation: OpSave, Key: "bad-save", ExpectedGeneration: state.Generation})
	if !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	engines[1].ClearFailure()
	invoke(t, s, OpRecover, nil, 0)
	if state = status(t, s); state.Running.Hash != previous || state.Pending != nil || state.RecoveryRequired {
		t.Fatal("explicit recovery failed")
	}
	_ = s.Close()
	s, err = Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if state = status(t, s); state.Running.Hash != previous || state.Pending != nil {
		t.Fatal("recovery lost stable anchor")
	}
}

func TestRBACRevocationAndSurfaceParity(t *testing.T) {
	for _, surface := range []Surface{Web, CLI, API} {
		t.Run(string(surface), func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			viewer := Principal{ID: "reader", Role: RoleViewer}
			before := status(t, s)
			for _, op := range []string{OpStage, OpValidate, OpCommit, OpConfirm, OpSave, OpRecover, OpRevoke} {
				_, err := s.Execute(context.Background(), viewer, surface, Request{Operation: op, Key: "denied", ExpectedGeneration: before.Generation})
				if !errors.Is(err, ErrDenied) {
					t.Fatalf("%s: %v", op, err)
				}
			}
			if _, err := s.History(viewer); !errors.Is(err, ErrDenied) {
				t.Fatal("viewer read protected history")
			}
			_, err := s.Execute(context.Background(), admin, surface, Request{Operation: OpRevoke, Key: "revoke", ExpectedGeneration: before.Generation, Target: viewer.ID})
			if err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			s, err = Open(dir, []Engine{NewSimEngine("one")}, Options{Boot: true})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err = s.Execute(context.Background(), viewer, surface, Request{Operation: OpStatus}); !errors.Is(err, ErrDenied) {
				t.Fatal("revocation lost on boot")
			}
			if history, err := s.History(admin); err != nil || len(history) < 10 {
				t.Fatal("history missing")
			}
		})
	}
}

func TestConcurrentRevisionAndLock(t *testing.T) {
	s, _, dir := fixture(t, Options{})
	if other, err := Open(dir, []Engine{NewSimEngine("one")}, Options{}); !errors.Is(err, ErrLocked) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatalf("lock: %v", err)
	}
	generation := status(t, s).Generation
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := sample(fmt.Sprintf("rule-%d", i))
			_, err := s.Execute(context.Background(), admin, API, Request{Operation: OpStage, Key: fmt.Sprintf("race-%d", i), ExpectedGeneration: generation, Config: &c})
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	passed, conflicts := 0, 0
	for err := range results {
		if err == nil {
			passed++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if passed != 1 || conflicts != 1 {
		t.Fatal("lost concurrent update")
	}
}

func TestStorageFaultAndAuditReserve(t *testing.T) {
	fault := false
	s, engines, dir := fixture(t, Options{Hook: func(point string) error {
		if fault && point == "before_persist" {
			return errors.New("read-only fixture")
		}
		return nil
	}})
	previous := status(t, s).Running.Hash
	c := sample("temporary")
	invoke(t, s, OpStage, &c, 0)
	invoke(t, s, OpCommit, nil, time.Second)
	fault = true
	_, err := s.Execute(context.Background(), Principal{ID: "viewer", Role: RoleViewer}, API, Request{Operation: OpSave})
	if !errors.Is(err, ErrStorage) {
		t.Fatal(err)
	}
	for _, e := range engines {
		if e.Current() != previous {
			t.Fatal("audit failure left temporary policy")
		}
	}
	_ = s.Close()
	s, err = Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if status(t, s).Running.Hash != previous {
		t.Fatal("pending recovery failed")
	}
	t.Run("reserved rollback", func(t *testing.T) {
		s, _, _ := fixture(t, Options{MaxRecords: 16})
		previous := status(t, s).Running.Hash
		c := sample("bounded")
		invoke(t, s, OpStage, &c, 0)
		invoke(t, s, OpCommit, nil, time.Second)
		for i := 0; i < 30; i++ {
			_, _ = s.Execute(context.Background(), Principal{ID: "viewer", Role: RoleViewer}, API, Request{Operation: OpSave})
		}
		s.mu.Lock()
		err := s.expire()
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if status(t, s).Running.Hash != previous {
			t.Fatal("audit flood consumed rollback reserve")
		}
	})
}

func TestCorruptStoreAndSymlink(t *testing.T) {
	s, _, dir := fixture(t, Options{})
	_ = s.Close()
	path := filepath.Join(dir, "00000001.json")
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, []Engine{NewSimEngine("one")}, Options{}); !errors.Is(err, ErrStorage) {
		t.Fatal("corruption accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, []Engine{NewSimEngine("one")}, Options{}); !errors.Is(err, ErrStorage) {
		t.Fatal("symlink accepted")
	}
}

func TestProcessInterruption(t *testing.T) {
	if os.Getenv("ANDEIVA_POC_CHILD") == "1" {
		dir := os.Getenv("ANDEIVA_POC_STATE")
		point := os.Getenv("ANDEIVA_POC_POINT")
		armed := false
		s, err := Open(dir, []Engine{NewSimEngine("one"), NewSimEngine("two")}, Options{Hook: func(stage string) error {
			if armed && stage == point {
				os.Exit(71)
			}
			return nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		c := sample("crash")
		invoke(t, s, OpStage, &c, 0)
		armed = true
		invoke(t, s, OpCommit, nil, 0)
		t.Fatal("crash hook missed")
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	for _, point := range []string{"after_intent", "after_apply:one", "after_apply:two", "before_receipt"} {
		t.Run(point, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProcessInterruption$")
			command.Env = append(os.Environ(), "ANDEIVA_POC_CHILD=1", "ANDEIVA_POC_STATE="+dir, "ANDEIVA_POC_POINT="+point)
			err := command.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 71 {
				t.Fatalf("child did not interrupt: %v", err)
			}
			s, err := Open(dir, []Engine{NewSimEngine("one"), NewSimEngine("two")}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			initial, _ := Canonical(Config{SchemaVersion: 1, DefaultAction: "deny"})
			if status(t, s).Running.Hash != initial.Hash {
				t.Fatal("interrupted commit survived")
			}
		})
	}
}

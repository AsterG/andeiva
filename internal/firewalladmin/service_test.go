package firewalladmin

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

type authorityFixture struct {
	engine              *configpoc.SimEngine
	state               LeaseState
	calls               int
	lostAck, badReceipt bool
}

func (a *authorityFixture) Arm(_ context.Context, id string, previous, target configpoc.Revision, ttl time.Duration) error {
	a.calls++
	a.state = LeaseState{Phase: "armed", ID: id, Previous: previous.Hash, Target: target.Hash, Deadline: time.Now().Add(ttl)}
	return nil
}
func (a *authorityFixture) Confirm(_ context.Context, id, hash string) error {
	a.calls++
	a.state.Phase = "idle"
	if a.badReceipt {
		a.state.ID = "different"
	}
	if a.lostAck {
		return errors.New("lost")
	}
	return nil
}
func (a *authorityFixture) Current(context.Context) (string, error) {
	a.calls++
	return a.engine.Current(), nil
}
func (a *authorityFixture) State(context.Context) (LeaseState, error) { a.calls++; return a.state, nil }

var operator = configpoc.Principal{ID: "operator", Role: configpoc.RoleAdmin}

func setup(t *testing.T) (*Service, *authorityFixture) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux journal")
	}
	e := configpoc.NewSimEngine("firewall")
	c := configpoc.Config{SchemaVersion: 2, DefaultAction: "deny"}
	core, err := configpoc.Open(filepath.Join(t.TempDir(), "state"), []configpoc.Engine{e}, configpoc.Options{Initial: &c})
	if err != nil {
		t.Fatal(err)
	}
	a := &authorityFixture{engine: e}
	s, err := New(core, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, a
}
func snapshot(t *testing.T, s *Service) configpoc.Snapshot {
	t.Helper()
	r, e := s.Execute(context.Background(), operator, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func staged(t *testing.T, s *Service) configpoc.Snapshot {
	t.Helper()
	r := snapshot(t, s)
	c := configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "tcp", Action: "allow", Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}}}}
	r, e := s.Execute(context.Background(), operator, configpoc.Web, configpoc.Request{Operation: configpoc.OpStage, Key: "stage", ExpectedGeneration: r.Generation, Config: &c})
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestDeniedNeverInvokesAuthority(t *testing.T) {
	s, a := setup(t)
	r := staged(t, s)
	for i, principal := range []configpoc.Principal{{ID: "viewer", Role: configpoc.RoleViewer}, {ID: "other", Role: configpoc.RoleAdmin}, {ID: "system", Role: configpoc.RoleAdmin}, {ID: "bad", Role: "invented"}} {
		_, err := s.Execute(context.Background(), principal, configpoc.API, configpoc.Request{Operation: configpoc.OpCommit, Key: fmt.Sprint("deny", i), ExpectedGeneration: r.Generation})
		if err == nil {
			t.Fatal("unauthorized commit")
		}
	}
	if a.calls != 0 {
		t.Fatalf("authority called %d", a.calls)
	}
}

func TestLostAckAndBadReceipt(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			s, a := setup(t)
			before := snapshot(t, s)
			r := staged(t, s)
			a.lostAck = true
			a.badReceipt = bad
			out, err := s.Execute(context.Background(), operator, configpoc.CLI, configpoc.Request{Operation: configpoc.OpCommit, Key: "commit", ExpectedGeneration: r.Generation})
			if !bad {
				if err != nil || out.Pending != nil || out.Running.Hash == before.Running.Hash {
					t.Fatalf("lost ack unreconciled %v", err)
				}
				return
			}
			if err == nil || !s.blocked || a.engine.Current() != before.Running.Hash {
				t.Fatal("uncertainty not blocked/compensated")
			}
			_, err = s.Execute(context.Background(), operator, configpoc.Web, configpoc.Request{Operation: configpoc.OpSave, Key: "save", ExpectedGeneration: out.Generation})
			if !errors.Is(err, configpoc.ErrRecovery) {
				t.Fatal("save after ambiguous confirmation")
			}
		})
	}
}

func TestConcurrentSaveHasSingleWinner(t *testing.T) {
	s, _ := setup(t)
	r := snapshot(t, s)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := s.Execute(context.Background(), operator, configpoc.API, configpoc.Request{Operation: configpoc.OpSave, Key: fmt.Sprint("save", i), ExpectedGeneration: r.Generation})
			results <- e
		}(i)
	}
	wg.Wait()
	close(results)
	winners := 0
	for e := range results {
		if e == nil {
			winners++
		} else if !errors.Is(e, configpoc.ErrConflict) {
			t.Fatal(e)
		}
	}
	if winners != 1 {
		t.Fatalf("winners %d", winners)
	}
}

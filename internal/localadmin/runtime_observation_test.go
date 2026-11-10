package localadmin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

type readbackAuthority struct {
	authority
	client *firewallipc.Client
}

func (a readbackAuthority) State(ctx context.Context) (firewalladmin.LeaseState, error) {
	return a.client.State(ctx)
}

func TestAdmittedStatusDisconnectDoesNotCloseSharedRPC(t *testing.T) {
	f := newFixture(t)
	a, b := net.Pipe()
	client, err := firewallipc.NewLocal(a, a, strings.Repeat("a", 32), 1, 42, func(configpoc.Config) (string, error) { return "digest", nil })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer b.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		scan := bufio.NewScanner(b)
		first := true
		for scan.Scan() {
			var m firewallipc.Message
			if json.Unmarshal(scan.Bytes(), &m) != nil {
				return
			}
			if first {
				first = false
				close(entered)
				<-release
			}
			if json.NewEncoder(b).Encode(firewallipc.Reply{Run: m.Run, Sequence: m.Sequence, Namespace: 42, State: firewalladmin.LeaseState{Phase: "idle"}}) != nil {
				return
			}
		}
	}()
	f.s.options.Authority = readbackAuthority{authority{f.m}, client}
	c := actor()
	c.Principal.Role = configpoc.RoleViewer
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		s, e := f.s.Status(ctx, c)
		if e == nil && s.Effective.RecoveryRequired {
			e = errors.New("readback unavailable")
		}
		result <- e
	}()
	<-entered
	cancel()
	close(release)
	if err = <-result; err != nil {
		t.Fatal("admitted read lost channel", err)
	}
	if s, e := f.s.Status(context.Background(), c); e != nil || s.Effective.RecoveryRequired {
		t.Fatal("next read must reuse healthy channel", e)
	}
	before := f.m.counts()
	if _, e := f.s.Status(ctx, c); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled admission accepted")
	}
	if f.m.counts() != before {
		t.Fatal("cancelled admission reached engine")
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
}

func TestRuntimeReadbackSerializesWithActivation(t *testing.T) {
	f := newFixture(t)
	f.stage(true)
	f.execute(f.request(configpoc.OpValidate))
	snap := f.snapshot()
	r := f.request(configpoc.OpCommit)
	r.Transaction.ConfirmFor = 30 * time.Second
	r.RecoveryProof = f.proof(actor(), r, snap.Candidate.Revision.Hash, r.Transaction.Key)
	entered, release := make(chan struct{}), make(chan struct{})
	f.m.mu.Lock()
	f.m.onApply = func() { close(entered); <-release }
	f.m.mu.Unlock()
	committed := make(chan error, 1)
	go func() { _, e := f.s.Execute(context.Background(), actor(), r); committed <- e }()
	<-entered
	observed := make(chan Status, 1)
	failure := make(chan error, 1)
	go func() {
		s, e := f.s.ObserveRuntime(context.Background())
		if e != nil {
			failure <- e
		} else {
			observed <- s
		}
	}()
	select {
	case <-observed:
		close(release)
		t.Fatal("monitor crossed activation")
	case e := <-failure:
		close(release)
		t.Fatal(e)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if e := <-committed; e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-failure:
		t.Fatal(e)
	case s := <-observed:
		if s.Effective.Hash != s.Snapshot.Running.Hash || s.Snapshot.Running.Hash != snap.Candidate.Revision.Hash || s.Snapshot.Generation != snap.Generation+1 {
			t.Fatal("incoherent readback")
		}
	}
	f.m.mu.Lock()
	f.m.onApply = nil
	f.m.badObservation = true
	f.m.mu.Unlock()
	if s, e := f.s.ObserveRuntime(context.Background()); !errors.Is(e, configpoc.ErrRecovery) || !s.Effective.RecoveryRequired || !s.Snapshot.RecoveryRequired {
		t.Fatal("unverified monitor succeeded", e)
	}
}

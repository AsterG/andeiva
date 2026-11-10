package localchannel

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/locallistener"
	"github.com/AsterG/andeiva/internal/localobserve"
)

func testBinding() Binding {
	return Binding{Run: strings.Repeat("a", 32), Instance: strings.Repeat("b", 32), Generation: 1, Namespace: 42, UID: 1001}
}

type worker struct{ hash string }

func (w *worker) Apply(_ context.Context, r configpoc.Revision) error { w.hash = r.Hash; return nil }
func (w *worker) Registry() (locallistener.Registry, error) {
	return locallistener.Registry{Hash: w.hash}, nil
}

type collector struct{ snapshot localobserve.Snapshot }

func (c collector) Observe() (localobserve.Snapshot, error) { return c.snapshot, nil }

func TestListenerOperationsUsePinnedChannel(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, b, testBinding(), &worker{}, nil) }()
	c, err := New(a, testBinding(), false)
	if err != nil {
		t.Fatal(err)
	}
	r, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Apply(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, err := c.Registry(ctx)
	if err != nil || got.Hash != r.Hash {
		t.Fatal(got, err)
	}
	if _, err = c.Observe(ctx); err == nil {
		t.Fatal("worker channel became observer")
	}
	_ = c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestObserverRejectsAnotherInstanceAndForeignSockets(t *testing.T) {
	for _, scenario := range []string{"valid", "instance", "namespace", "foreign", "capacity"} {
		t.Run(scenario, func(t *testing.T) {
			binding := testBinding()
			s := localobserve.Snapshot{RunID: binding.Run, Instance: binding.Instance, Generation: binding.Generation, Namespace: binding.Namespace, StartTime: 5}
			switch scenario {
			case "instance":
				s.Instance = strings.Repeat("c", 32)
			case "namespace":
				s.Namespace++
			case "foreign":
				s.Foreign = []localobserve.Socket{{Port: 8080}}
			case "capacity":
				s.Sockets = make([]localobserve.Socket, 9)
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			go func() { _ = Serve(ctx, b, binding, nil, collector{s}) }()
			c, err := New(a, binding, true)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Observe(ctx)
			if (err == nil) != (scenario == "valid") {
				t.Fatal(err)
			}
			if _, err = c.Registry(ctx); err == nil {
				t.Fatal("observer channel became worker")
			}
		})
	}
}

func TestProtocolViolationsCloseBeforeWorker(t *testing.T) {
	for _, scenario := range []string{"run", "sequence", "role", "read_payload", "hash"} {
		t.Run(scenario, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			w := &worker{}
			done := make(chan error, 1)
			go func() { done <- Serve(ctx, b, testBinding(), w, nil) }()
			m := message{Binding: testBinding(), Sequence: 1, Operation: "registry"}
			switch scenario {
			case "run":
				m.Binding.Run = strings.Repeat("c", 32)
			case "sequence":
				m.Sequence = 2
			case "role":
				m.Operation = "kernel"
			case "read_payload":
				m.Revision = &configpoc.Revision{}
			case "hash":
				m.Operation = "apply"
				m.Revision = &configpoc.Revision{}
			}
			if err := json.NewEncoder(a).Encode(m); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("invalid message accepted")
				}
			case <-ctx.Done():
				t.Fatal("invalid message did not close")
			}
			if w.hash != "" {
				t.Fatal("worker mutated before validation")
			}
		})
	}
}

func TestTimeoutPoisonsChannel(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c, err := New(a, testBinding(), false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err = c.Registry(ctx); err == nil {
		t.Fatal("stalled channel accepted")
	}
	if _, err = c.Registry(context.Background()); err == nil {
		t.Fatal("timed-out channel reused")
	}
}

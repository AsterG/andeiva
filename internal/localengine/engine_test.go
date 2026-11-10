package localengine

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

type kernel struct {
	data                                    []byte
	checkFail, applyFail, lostAck, readFail bool
	calls                                   int
}

func (k *kernel) Check(context.Context, []byte) error {
	if k.checkFail {
		return ErrState
	}
	return nil
}
func (k *kernel) Apply(_ context.Context, batch []byte) error {
	k.calls++
	if k.applyFail {
		return ErrState
	}
	var input struct {
		NFT []map[string]map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(batch, &input); err != nil {
		return err
	}
	objects := []map[string]any{}
	for _, command := range input.NFT {
		if add, ok := command["add"]; ok {
			if rule, ok := add["rule"].(map[string]any); ok {
				for _, raw := range rule["expr"].([]any) {
					expr := raw.(map[string]any)
					if _, ok := expr["counter"]; ok {
						expr["counter"] = map[string]any{"packets": 0, "bytes": 0}
					}
				}
			}
			objects = append(objects, add)
		}
	}
	k.data, _ = json.Marshal(map[string]any{"nftables": objects})
	if k.lostAck {
		return ErrState
	}
	return nil
}
func (k *kernel) Observe(context.Context) ([]byte, bool, error) {
	if k.readFail {
		return nil, false, ErrState
	}
	return k.data, k.data != nil, nil
}

type listenerFixture struct {
	actual               []localpolicy.Listener
	fail, readFail, omit bool
}

func (l *listenerFixture) Apply(_ context.Context, r configpoc.Revision) error {
	l.actual = nil
	if l.fail {
		return ErrState
	}
	if r.Config.LocalServices == nil {
		return nil
	}
	for _, s := range r.Config.LocalServices.Services {
		if !s.Enabled {
			continue
		}
		for _, b := range s.Bindings {
			if l.omit {
				continue
			}
			l.actual = append(l.actual, localpolicy.Listener{Owner: s.Owner, Service: s.ID, Interface: b.Interface, LocalAddress: b.LocalAddress, Protocol: s.Endpoints[0].Protocol, Port: s.Endpoints[0].FirstPort})
		}
	}
	return nil
}
func (l *listenerFixture) Observe(context.Context) ([]localpolicy.Listener, error) {
	if l.readFail {
		return nil, ErrState
	}
	return append([]localpolicy.Listener(nil), l.actual...), nil
}

func revision(t *testing.T, port uint16) configpoc.Revision {
	t.Helper()
	i := localpolicy.Interface{Name: "src0", Zone: localpolicy.LAN, Addresses: []string{"198.18.1.1"}}
	s, err := localpolicy.DefaultManagement("management", "https", i, "198.18.1.1", []string{"198.18.1.2/32"})
	if err != nil {
		t.Fatal(err)
	}
	s.Endpoints[0].FirstPort, s.Endpoints[0].LastPort = port, port
	c := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{i}, Services: []localpolicy.Service{s}}
	r, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", Rules: []configpoc.Rule{}, LocalServices: &c})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func setup(t *testing.T) (*Engine, *kernel, *listenerFixture, configpoc.Revision) {
	t.Helper()
	r := revision(t, 18443)
	k, l := &kernel{}, &listenerFixture{}
	e, err := New(k, l, r.Config.LocalServices.Interfaces, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e, k, l, r
}

func TestBothComponentsMustBeObserved(t *testing.T) {
	for _, failure := range []string{"kernel_check", "kernel_apply", "kernel_lost_ack", "listener_apply", "listener_missing", "listener_observe", "kernel_observe"} {
		t.Run(failure, func(t *testing.T) {
			e, k, l, initial := setup(t)
			if err := e.Apply(context.Background(), initial); err != nil {
				t.Fatal(err)
			}
			target := revision(t, 19443)
			switch failure {
			case "kernel_check":
				k.checkFail = true
			case "kernel_apply":
				k.applyFail = true
			case "kernel_lost_ack":
				k.lostAck = true
			case "listener_apply":
				l.fail = true
			case "listener_missing":
				l.omit = true
			case "listener_observe":
				l.readFail = true
			case "kernel_observe":
				k.readFail = true
			}
			if err := e.Apply(context.Background(), target); err == nil {
				t.Fatal("failure accepted")
			}
			if e.Current() == target.Hash {
				t.Fatal("unverified target published")
			}
			k.checkFail, k.applyFail, k.lostAck, k.readFail = false, false, false, false
			l.fail, l.omit, l.readFail = false, false, false
			if err := e.Apply(context.Background(), initial); err != nil {
				t.Fatal("compensation", err)
			}
			if e.Current() != initial.Hash {
				t.Fatal("compensation not observed")
			}
		})
	}
}

func TestDriftInvalidatesRevisionAndFreshEngineCannotAdoptTable(t *testing.T) {
	e, k, l, r := setup(t)
	if err := e.Apply(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	other, err := New(k, l, r.Config.LocalServices.Interfaces, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Apply(context.Background(), r); !errors.Is(err, ErrState) {
		t.Fatal("adopted existing table", err)
	}
	l.actual = append(l.actual, localpolicy.Listener{Owner: "foreign", Port: 19000})
	if e.Current() != "" {
		t.Fatal("extra listener accepted")
	}
	if err := e.Apply(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	k.data = []byte(`{"nftables":[]}`)
	if e.Current() != "" {
		t.Fatal("missing effective rules accepted")
	}
}

func TestRejectedInventoryForwardingAndHashHaveNoEffects(t *testing.T) {
	for _, mutation := range []string{"inventory", "forwarding", "hash"} {
		t.Run(mutation, func(t *testing.T) {
			e, k, _, r := setup(t)
			switch mutation {
			case "inventory":
				r.Config.LocalServices.Interfaces[0].Addresses = append(r.Config.LocalServices.Interfaces[0].Addresses, "198.18.1.9")
			case "forwarding":
				r.Config.Rules = []configpoc.Rule{{ID: "forbidden", Action: "allow"}}
			case "hash":
				r.Hash = "wrong"
			}
			if e.Apply(context.Background(), r) == nil || k.calls != 0 {
				t.Fatal("invalid activation performed")
			}
		})
	}
}

func TestLegacyRevisionRemovesOnlyManagedServices(t *testing.T) {
	e, _, l, r := setup(t)
	if err := e.Apply(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	legacy, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Apply(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	if len(l.actual) != 0 || e.Current() != legacy.Hash {
		t.Fatal("residual listener or wrong envelope")
	}
}

func TestConcurrentObservationAndActivation(t *testing.T) {
	e, _, _, r := setup(t)
	if err := e.Apply(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				if e.Current() != r.Hash {
					t.Error("partial publication")
				}
			}
		})
	}
	wg.Go(func() {
		for range 10 {
			if err := e.Apply(context.Background(), r); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Wait()
}

func TestObservationCannotMutateTrustedExpectedState(t *testing.T) {
	e, _, _, r := setup(t)
	if err := e.Apply(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	observed, err := e.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	observed.Local.Rules[0].Action = "deny"
	observed.Local.Listeners[0].Port = 19999
	if e.Current() != r.Hash {
		t.Fatal("caller mutated engine expectation")
	}
}

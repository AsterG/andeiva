package networkexecutor

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/AsterG/andeiva/internal/networkplan"
)

func fixturePlan() networkplan.Revision {
	r, err := networkplan.Canonical(networkplan.Config{SchemaVersion: 1, IPv6Forwarding: "deny", Interfaces: []networkplan.Interface{
		{ID: "lan", Role: networkplan.LAN, Zone: "inside", Binding: networkplan.Binding{Name: "lan0", HardwareAddress: "02:00:00:00:01:01"}, IPv4: networkplan.IPv4{Mode: "static", Address: "198.18.0.1/24"}},
		{ID: "wan", Role: networkplan.WAN, Zone: "outside", Binding: networkplan.Binding{Name: "wan0", HardwareAddress: "02:00:00:00:02:01"}, IPv4: networkplan.IPv4{Mode: "static", Address: "198.19.0.1/24", Gateway: "198.19.0.2"}},
	}, Zones: []networkplan.Zone{{ID: "inside", Kind: networkplan.LAN}, {ID: "outside", Kind: networkplan.WAN}}, DefaultRoute: networkplan.DefaultRoute{InterfaceID: "wan", Metric: 10}, DNS: networkplan.DNS{Mode: "none", Servers: []string{}}})
	if err != nil {
		panic(err)
	}
	return r
}

type fakeKernel struct {
	state       observation
	mutations   int
	failAt      int
	afterEffect bool
	failDelete  bool
	cancel      context.CancelFunc
	spoof       bool
}

func fakeExecutor() (*Executor, *fakeKernel) {
	f := &fakeKernel{state: observation{Links: []link{
		{Index: 1, Name: "lan0", MAC: "02:00:00:00:01:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []address{}},
		{Index: 2, Name: "wan0", MAC: "02:00:00:00:02:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []address{}},
	}, Routes: []route{}}}
	return &Executor{lifetime: context.Background(), run: f.run}, f
}
func (f *fakeKernel) run(ctx context.Context, op operation) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch op.kind {
	case "addresses":
		return json.Marshal(f.state.Links)
	case "routes":
		return json.Marshal(f.state.Routes)
	}
	f.mutations++
	failure := f.mutations == f.failAt
	if failure && !f.afterEffect {
		return nil, ErrCommand
	}
	if f.failDelete && (op.kind == "address-delete" || op.kind == "route-delete") {
		return nil, ErrCommand
	}
	switch op.kind {
	case "address-add":
		p := netip.MustParsePrefix(op.address)
		for n, l := range f.state.Links {
			if l.Name == op.name {
				f.state.Links[n].Addresses = append(l.Addresses, address{Family: "inet", Local: p.Addr().String(), Bits: p.Bits(), Scope: "global", Label: l.Name, Valid: 4294967295, Preferred: 4294967295})
			}
		}
		f.state.Routes = append(f.state.Routes, route{Destination: p.Masked().String(), Device: op.name, Protocol: "kernel", Scope: "link", Source: p.Addr().String(), Table: "main", Type: "unicast"}, route{Destination: p.Addr().String(), Device: op.name, Protocol: "kernel", Scope: "host", Source: p.Addr().String(), Table: "local", Type: "local"})
	case "address-delete":
		for n, l := range f.state.Links {
			if l.Name == op.name {
				f.state.Links[n].Addresses = []address{}
			}
		}
		kept := []route{}
		for _, r := range f.state.Routes {
			if r.Device != op.name || r.Protocol != "kernel" {
				kept = append(kept, r)
			}
		}
		f.state.Routes = kept
	case "route-add":
		f.state.Routes = append(f.state.Routes, route{Destination: "default", Device: op.name, Gateway: op.gateway, Protocol: "static", Scope: "global", Table: "main", Type: "unicast", Metric: op.metric})
	case "route-delete":
		kept := []route{}
		for _, r := range f.state.Routes {
			if r.Destination != "default" {
				kept = append(kept, r)
			}
		}
		f.state.Routes = kept
	default:
		return nil, ErrScope
	}
	if f.spoof && f.mutations == 3 {
		f.state.Links[0].Index = 99
	}
	if failure {
		if f.cancel != nil {
			f.cancel()
		}
		return nil, ErrCommand
	}
	return nil, nil
}
func TestApplyRestoreExact(t *testing.T) {
	e, f := fakeExecutor()
	baseline, _ := json.Marshal(f.state)
	if err := e.Apply(context.Background(), fixturePlan()); err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(context.Background(), fixturePlan()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if err := e.Restore(); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(f.state)
	if string(after) != string(baseline) {
		t.Fatalf("baseline changed: %s", after)
	}
	if err := e.Apply(context.Background(), fixturePlan()); err != nil {
		t.Fatal(err)
	}
	if err := e.Restore(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDriftFencesWithoutMutations(t *testing.T) {
	e, f := fakeExecutor()
	if err := e.Apply(context.Background(), fixturePlan()); err != nil {
		t.Fatal(err)
	}
	f.state.Routes = append(f.state.Routes, route{Destination: "203.0.113.0/24"})
	before := f.mutations
	if err := e.Verify(context.Background()); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	if !e.fenced || f.mutations != before || !errors.Is(e.Restore(), ErrUncertain) {
		t.Fatal("readback drift was not fenced")
	}
}
func TestEveryMutationFailureCompensates(t *testing.T) {
	for n := 1; n <= 3; n++ {
		for _, after := range []bool{false, true} {
			t.Run(strconv.Itoa(n)+strconv.FormatBool(after), func(t *testing.T) {
				e, f := fakeExecutor()
				f.failAt = n
				f.afterEffect = after
				baseline, _ := json.Marshal(f.state)
				if err := e.Apply(context.Background(), fixturePlan()); err == nil {
					t.Fatal("failure hidden")
				}
				got, _ := json.Marshal(f.state)
				if string(got) != string(baseline) || e.fenced || e.active != nil {
					t.Fatalf("not exactly restored: %s fenced=%v", got, e.fenced)
				}
			})
		}
	}
}
func TestRequestCancellationStillRestores(t *testing.T) {
	e, f := fakeExecutor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.failAt = 2
	f.afterEffect = true
	f.cancel = cancel
	if err := e.Apply(ctx, fixturePlan()); err == nil {
		t.Fatal("failure hidden")
	}
	if e.fenced || !f.state.empty() {
		t.Fatal("request cancellation blocked compensation")
	}
}
func TestUncertaintyIsSticky(t *testing.T) {
	for _, identity := range []bool{false, true} {
		t.Run(strconv.FormatBool(identity), func(t *testing.T) {
			e, f := fakeExecutor()
			if identity {
				f.spoof = true
				_ = e.Apply(context.Background(), fixturePlan())
			} else {
				if err := e.Apply(context.Background(), fixturePlan()); err != nil {
					t.Fatal(err)
				}
				f.failDelete = true
				_ = e.Restore()
			}
			before := f.mutations
			if !errors.Is(e.Apply(context.Background(), fixturePlan()), ErrUncertain) || !errors.Is(e.Restore(), ErrUncertain) || f.mutations != before {
				t.Fatal("fence reopened")
			}
		})
	}
}
func TestRejectUnsupportedBeforeEffects(t *testing.T) {
	for _, kind := range []string{"dhcp", "dns", "hash", "binding", "occupied", "route", "prefix"} {
		t.Run(kind, func(t *testing.T) {
			e, f := fakeExecutor()
			r := fixturePlan()
			switch kind {
			case "dhcp":
				r.Config.Interfaces[1].IPv4 = networkplan.IPv4{Mode: "dhcp"}
				r, _ = networkplan.Canonical(r.Config)
			case "dns":
				r.Config.DNS = networkplan.DNS{Mode: "static", Servers: []string{"198.19.0.2"}}
				r, _ = networkplan.Canonical(r.Config)
			case "hash":
				r.Hash = "tampered"
			case "binding":
				f.state.Links[0].MAC = "02:00:00:00:00:ff"
			case "occupied":
				f.state.Links[0].Addresses = []address{{Family: "inet", Local: "198.18.0.99", Bits: 24}}
			case "route":
				f.state.Routes = []route{{Destination: "default"}}
			case "prefix":
				r.Config.Interfaces[0].IPv4.Address = "198.18.0.1/32"
				r, _ = networkplan.Canonical(r.Config)
			}
			if err := e.Apply(context.Background(), r); err == nil || f.mutations != 0 {
				t.Fatal("unsupported input had effects", err, f.mutations)
			}
		})
	}
}
func TestSerializedApplications(t *testing.T) {
	e, _ := fakeExecutor()
	var wg sync.WaitGroup
	var successes int
	var mu sync.Mutex
	for range 16 {
		wg.Go(func() {
			err := e.Apply(context.Background(), fixturePlan())
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			} else if !errors.Is(err, ErrBusy) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if successes != 1 {
		t.Fatal(successes)
	}
	if err := e.Restore(); err != nil {
		t.Fatal(err)
	}
}
func TestReadbackRejectsExtraAndMissingState(t *testing.T) {
	for _, kind := range []string{"extra-route", "missing-route", "address", "metric", "lifetime", "flags", "extra-address"} {
		t.Run(kind, func(t *testing.T) {
			e, f := fakeExecutor()
			r := fixturePlan()
			if err := e.Apply(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "extra-route":
				f.state.Routes = append(f.state.Routes, route{Destination: "203.0.113.0/24"})
			case "missing-route":
				f.state.Routes = f.state.Routes[1:]
			case "address":
				f.state.Links[0].Addresses[0].Local = "198.18.0.99"
			case "metric":
				for i := range f.state.Routes {
					if f.state.Routes[i].Destination == "default" {
						f.state.Routes[i].Metric++
					}
				}
			case "lifetime":
				f.state.Links[0].Addresses[0].Valid = 30
			case "flags":
				f.state.Routes[0].Flags = []string{"dead"}
			case "extra-address":
				f.state.Links[0].Addresses = append(f.state.Links[0].Addresses, f.state.Links[0].Addresses[0])
			}
			o, err := e.observe(context.Background())
			if err == nil && o.matches(r, e.active.baseline) {
				t.Fatal("false verified readback")
			}
		})
	}
}
func TestMalformedReadback(t *testing.T) {
	for _, payload := range []string{"null", "{}", "[] []", "[", string(make([]byte, maxOutput+1))} {
		e, _ := fakeExecutor()
		e.run = func(context.Context, operation) ([]byte, error) { return []byte(payload), nil }
		if err := e.Apply(context.Background(), fixturePlan()); err == nil {
			t.Fatalf("accepted malformed %q", payload[:min(20, len(payload))])
		}
	}
}
func TestCommandGuard(t *testing.T) {
	for _, op := range []operation{{kind: "shell"}, {kind: "address-add", name: "-bad", address: "198.18.0.1/24"}, {kind: "address-add", name: "lan0", address: "198.18.0.1/24;id"}, {kind: "route-add", name: "wan0", gateway: "::1", metric: 10}, {kind: "route-add", name: "wan0", gateway: "198.19.0.2", metric: 0}} {
		if _, err := arguments(op); err == nil {
			t.Fatal(op)
		}
	}
	args, err := arguments(operation{kind: "route-add", name: "wan0", gateway: "198.19.0.2", metric: 10})
	if err != nil || !reflect.DeepEqual(args, []string{"-4", "route", "add", "default", "via", "198.19.0.2", "dev", "wan0", "proto", "static", "metric", "10"}) {
		t.Fatal(args, err)
	}
}
func TestZeroAndClosedExecutors(t *testing.T) {
	var zero Executor
	if err := zero.Apply(context.Background(), fixturePlan()); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
	e, _ := fakeExecutor()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(e.Apply(context.Background(), fixturePlan()), ErrScope) {
		t.Fatal("closed executor admitted")
	}
}

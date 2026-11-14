package previewruntime

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
)

// Driver doubles model namespace exclusivity and physical emptiness. They do
// not represent native netlink, LAN bootstrap or actual DHCP evidence.
type selectorDriverFixtureV4 struct {
	active, closed, foreign bool
	plan                    string
	writes, restores        int
	onClose                 func()
}

func (d *selectorDriverFixtureV4) Prepare(_ context.Context, r networkplan.Revision) (networkexecutor.PreparedSnapshot, error) {
	if d.closed || d.active || d.foreign {
		return networkexecutor.PreparedSnapshot{}, ErrIdentity
	}
	d.plan = r.Hash
	return networkexecutor.PreparedSnapshot{Version: 1, PlanHash: r.Hash, Hash: strings.Repeat("a", 64)}, nil
}
func (d *selectorDriverFixtureV4) VerifyPrepared(_ context.Context, p networkexecutor.PreparedSnapshot) error {
	if d.closed || d.active || d.foreign || d.plan != p.PlanHash {
		return ErrIdentity
	}
	return nil
}
func (d *selectorDriverFixtureV4) ApplyPrepared(ctx context.Context, r networkplan.Revision, p networkexecutor.PreparedSnapshot) error {
	if d.VerifyPrepared(ctx, p) != nil || r.Hash != d.plan {
		return ErrIdentity
	}
	d.active = true
	d.writes++
	return nil
}
func (d *selectorDriverFixtureV4) RestorePrepared(_ context.Context, p networkexecutor.PreparedSnapshot) error {
	if d.closed || d.foreign || p.PlanHash != d.plan {
		return ErrIdentity
	}
	d.active = false
	d.restores++
	return nil
}
func (d *selectorDriverFixtureV4) Verify(context.Context) error {
	if d.closed || d.foreign || !d.active {
		return ErrIdentity
	}
	return nil
}
func (d *selectorDriverFixtureV4) PrepareObserved(context.Context, []networkplan.Binding) (networkexecutor.ObservedSnapshot, error) {
	if d.closed || d.active || d.foreign {
		return networkexecutor.ObservedSnapshot{}, ErrIdentity
	}
	return networkexecutor.ObservedSnapshot{Version: 1, Hash: strings.Repeat("b", 64)}, nil
}
func (d *selectorDriverFixtureV4) VerifyObserved(ctx context.Context, _ networkexecutor.ObservedSnapshot) error {
	_, e := d.PrepareObserved(ctx, nil)
	return e
}
func (d *selectorDriverFixtureV4) RecoverObserved(ctx context.Context, s networkexecutor.ObservedSnapshot, _ networkexecutor.OwnedNamespaceIdentity) error {
	return d.VerifyObserved(ctx, s)
}
func (d *selectorDriverFixtureV4) RecoverPrepared(_ context.Context, r networkplan.Revision, _ networkexecutor.PreparedSnapshot, _ networkexecutor.OwnedNamespaceIdentity) error {
	if d.foreign || d.closed {
		return ErrIdentity
	}
	d.plan = r.Hash
	return nil
}
func (d *selectorDriverFixtureV4) Close() error {
	if d.active {
		return ErrIdentity
	}
	d.closed = true
	if d.onClose != nil {
		d.onClose()
	}
	return nil
}

func selectorPlansV4(t *testing.T) (networkplan.Revision, networkplan.Revision, []networkplan.Binding) {
	t.Helper()
	b, _ := routedDeferredFixtureV4(t)
	dhcp := b.Desired
	copy, err := cloneRoutedDHCPDeferredBindingV4(b)
	if err != nil {
		t.Fatal(err)
	}
	var bindings []networkplan.Binding
	for i := range copy.Desired.Config.Interfaces {
		iface := &copy.Desired.Config.Interfaces[i]
		bindings = append(bindings, iface.Binding)
		if iface.Role == networkplan.WAN {
			iface.IPv4 = networkplan.IPv4{Mode: "static", Address: "198.19.0.10/24", Gateway: "198.19.0.1"}
		}
	}
	static, err := networkplan.Canonical(copy.Desired.Config)
	if err != nil {
		t.Fatal(err)
	}
	return static, dhcp, bindings
}
func selectorFixtureV4(t *testing.T) (*routedNetworkSelectorV4, *[]*selectorDriverFixtureV4) {
	t.Helper()
	_, _, bindings := selectorPlansV4(t)
	var drivers []*selectorDriverFixtureV4
	live := 0
	s, err := newRoutedNetworkSelectorV4(context.Background(), bindings, func(_ context.Context, r *networkplan.Revision) (routedNetworkDriverV4, *networkexecutor.LANBootstrapV3, error) {
		if live != 0 {
			t.Error("two simultaneous namespace owners")
			return nil, nil, ErrIdentity
		}
		live++
		d := &selectorDriverFixtureV4{onClose: func() { live-- }}
		drivers = append(drivers, d)
		var lan *networkexecutor.LANBootstrapV3
		if r != nil {
			_, dhcp, e := routedNetworkProfileV4(*r)
			if e != nil {
				return nil, nil, e
			}
			if dhcp {
				lan = &networkexecutor.LANBootstrapV3{}
			}
		}
		return d, lan, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, &drivers
}

func TestRoutedNetworkSelectorV4FirstStaticAndDHCPFromNoNetwork(t *testing.T) {
	for _, mode := range []string{"static", "dhcp"} {
		t.Run(mode, func(t *testing.T) {
			s, drivers := selectorFixtureV4(t)
			static, dhcp, bindings := selectorPlansV4(t)
			target := static
			if mode == "dhcp" {
				target = dhcp
			}
			ctx := context.Background()
			observed, err := s.PrepareObserved(ctx, bindings)
			if err != nil {
				t.Fatal(err)
			}
			p, err := s.Prepare(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range *drivers {
				if d.writes != 0 {
					t.Fatal("Prepare changed L3")
				}
			}
			if s.VerifyObserved(ctx, observed) != nil {
				t.Fatal("NoNetwork proof lost during preview")
			}
			if err = s.ApplyPrepared(ctx, target, p); err != nil || s.Verify(ctx) != nil {
				t.Fatal("first apply failed", err)
			}
			if _, err = s.Prepare(ctx, dhcp); err == nil {
				t.Fatal("configured driver allowed plan replacement")
			}
			if mode == "dhcp" {
				r, lan, e := s.DHCP()
				if e != nil || r.Hash != target.Hash || lan != s.lan {
					t.Fatal("DHCP lane does not retain same LAN instance")
				}
			}
			stopped := false
			s.beforeRestore = func(context.Context) error { stopped = true; return nil }
			if s.RestorePrepared(ctx, p) != nil || !stopped || s.VerifyObserved(ctx, observed) != nil {
				t.Fatal("inverse did not restore exact empty scope")
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestRoutedNetworkSelectorV4CandidateChangesStayReadOnly(t *testing.T) {
	s, drivers := selectorFixtureV4(t)
	static, dhcp, _ := selectorPlansV4(t)
	ctx := context.Background()
	for _, plan := range []networkplan.Revision{dhcp, static, dhcp} {
		if _, err := s.Prepare(ctx, plan); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range *drivers {
		if d.writes != 0 || d.restores != 0 {
			t.Fatal("unselected candidate caused effects")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestRoutedNetworkSelectorV4RejectsForeignAndUnselectedMementos(t *testing.T) {
	s, drivers := selectorFixtureV4(t)
	static, dhcp, _ := selectorPlansV4(t)
	ctx := context.Background()
	(*drivers)[0].foreign = true
	if _, err := s.Prepare(ctx, dhcp); err == nil || (*drivers)[0].closed {
		t.Fatal("foreign occupied scope switched writer")
	}
	(*drivers)[0].foreign = false
	p, err := s.Prepare(ctx, static)
	if err != nil {
		t.Fatal(err)
	}
	bad := p
	bad.PlanHash = dhcp.Hash
	if s.ApplyPrepared(ctx, dhcp, bad) == nil || s.RestorePrepared(ctx, bad) == nil {
		t.Fatal("foreign plan used prepared capability")
	}
	if s.ApplyPrepared(ctx, static, p) != nil {
		t.Fatal("valid apply failed")
	}
	s.beforeRestore = func(context.Context) error { return ErrUnavailable }
	if s.RestorePrepared(ctx, p) == nil || (*drivers)[0].restores != 0 || s.Verify(ctx) != nil {
		t.Fatal("unconfirmed acquisition stop allowed LAN restore")
	}
}
func TestRoutedNetworkSelectorV4SerialCandidatePreparation(t *testing.T) {
	s, drivers := selectorFixtureV4(t)
	static, dhcp, _ := selectorPlansV4(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		r := static
		if i%2 == 0 {
			r = dhcp
		}
		wg.Go(func() {
			_, err := s.Prepare(context.Background(), r)
			if err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for _, d := range *drivers {
		if d.writes != 0 {
			t.Fatal("concurrent prepare applied candidate")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

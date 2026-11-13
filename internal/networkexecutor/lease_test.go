package networkexecutor

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkplan"
)

const defaultRulesFixture = `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`

func leaseInputs(t *testing.T) (*Executor, *fakeKernel, LeaseOptions, *LeaseFact, *int64) {
	t.Helper()
	e, k := fakeExecutor()
	r := fixturePlan()
	if _, err := k.run(context.Background(), operation{kind: "address-add", name: "lan0", address: r.Config.Interfaces[0].IPv4.Address}); err != nil {
		t.Fatal(err)
	}
	k.mutations = 0
	id := recoveryIdentityFixture()
	e.identity = &id
	r.Config.Interfaces[1].IPv4 = networkplan.IPv4{Mode: "dhcp"}
	r, err := networkplan.Canonical(r.Config)
	if err != nil {
		t.Fatal(err)
	}
	owner := LeaseOwner{Namespace: id.Namespace, BootID: id.BootID, RunID: id.RunID, Incarnation: strings.Repeat("b", 32), PID: 50, StartTicks: 12345}
	fact := &LeaseFact{Owner: owner, Sequence: 1, DesiredHash: r.Hash, WAN: r.Config.Interfaces[1].Binding, Address: "198.19.0.1/24", Gateway: "198.19.0.2", DeadlineBootNS: int64(240 * time.Second)}
	now := int64(100 * time.Second)
	e.run = func(ctx context.Context, op operation) ([]byte, error) {
		if op.kind == "rules" {
			return []byte(defaultRulesFixture), nil
		}
		return k.run(ctx, op)
	}
	options := LeaseOptions{Desired: r, Owner: owner, Current: func(context.Context) (LeaseFact, error) { return *fact, nil }}
	return e, k, options, fact, &now
}

func leaseFixture(t *testing.T) (*LeaseExecutor, *fakeKernel, *LeaseFact, *int64) {
	t.Helper()
	e, k, options, fact, now := leaseInputs(t)
	l, err := newLeaseExecutor(context.Background(), e, options, func() (int64, error) { return *now, nil })
	if err != nil {
		t.Fatal("constructor", err)
	}
	if k.mutations != 0 {
		t.Fatal("constructor mutated")
	}
	return l, k, fact, now
}

func TestLeaseExecutorRejectsAuthorityChangeDuringFinalReadback(t *testing.T) {
	for _, hadWAN := range []bool{false, true} {
		for _, change := range []string{"expired", "revoked", "new-sequence"} {
			name := change
			if hadWAN {
				name += "-replacing-wan"
			}
			t.Run(name, func(t *testing.T) {
				l, k, fact, now := leaseFixture(t)
				mutationsAtReadback := 2
				want := LeaseBaselineRestored
				if hadWAN {
					if out, err := l.Refresh(context.Background()); err != nil || out != LeaseApplied {
						t.Fatal("initial lease", out, err)
					}
					fact.Sequence++
					fact.Address = "198.19.0.3/24"
					mutationsAtReadback = 6 // Withdraw the prior WAN, then apply the new tuple.
					want = LeaseWANWithdrawn
				}
				run := l.base.run
				fired := false
				l.base.run = func(ctx context.Context, op operation) ([]byte, error) {
					data, err := run(ctx, op)
					if !fired && op.kind == "routes" && k.mutations == mutationsAtReadback {
						fired = true
						switch change {
						case "expired":
							*now = fact.DeadlineBootNS
						case "revoked":
							fact.Revoked = true
						case "new-sequence":
							fact.Sequence++
						}
					}
					return data, err
				}
				out, err := l.Refresh(context.Background())
				if !fired || err == nil || out != want {
					t.Fatal("stale readback published as applied", fired, out, err)
				}
				observed, err := l.base.observe(context.Background())
				if err != nil || !reflect.DeepEqual(observed, l.baseline) {
					t.Fatal("stale WAN or previous tuple survived compensation", err)
				}
			})
		}
	}
}

func TestLeaseExecutorPreservesLANAndRestoresOnlyOwnWAN(t *testing.T) {
	l, k, fact, _ := leaseFixture(t)
	if l.desired.Config.Interfaces[1].IPv4.Mode != "dhcp" {
		t.Fatal("desired mode rewritten")
	}
	baseline := l.baseline
	out, err := l.Refresh(context.Background())
	if err != nil || out != LeaseApplied || k.mutations != 2 || l.Verify(context.Background()) != nil {
		t.Fatal(out, err, k.mutations)
	}
	if l.Close() != ErrBusy {
		t.Fatal("close discarded installed ownership")
	}
	count := k.mutations
	if _, err := l.Refresh(context.Background()); !errors.Is(err, ErrScope) || k.mutations != count {
		t.Fatal("replayed sequence had effects", err)
	}
	fact.Sequence++
	fact.DeadlineBootNS += int64(time.Second)
	if out, err = l.Refresh(context.Background()); err != nil || out != LeaseEvidenceRefreshed || k.mutations != count {
		t.Fatal("same tuple renewal", out, err)
	}
	if out, err = l.Withdraw(context.Background()); err != nil || out != LeaseBaselineRestored {
		t.Fatal(out, err)
	}
	o, err := l.base.observe(context.Background())
	if err != nil || !reflect.DeepEqual(o, baseline) {
		t.Fatal("baseline not restored", err)
	}
	if k.mutations != 4 || l.Close() != nil {
		t.Fatal("unexpected cleanup")
	}
}

func TestLeaseExecutorRejectsOccupiedWANAndForeignBaseline(t *testing.T) {
	for _, kind := range []string{"wan", "lan", "route", "rules", "owner", "namespace", "no-identity", "dns"} {
		t.Run(kind, func(t *testing.T) {
			e, k, o, _, now := leaseInputs(t)
			switch kind {
			case "wan":
				_, _ = k.run(context.Background(), operation{kind: "address-add", name: "wan0", address: "198.19.0.1/24"})
			case "lan":
				k.state.Links[0].Addresses[0].Local = "198.18.0.99"
			case "route":
				k.state.Routes = append(k.state.Routes, route{Destination: "default", Device: "wan0"})
			case "rules":
				prior := e.run
				e.run = func(ctx context.Context, op operation) ([]byte, error) {
					if op.kind == "rules" {
						return []byte(strings.Replace(defaultRulesFixture, `"table":"main"`, `"table":"123"`, 1)), nil
					}
					return prior(ctx, op)
				}
			case "owner":
				o.Owner.Incarnation = "untrusted"
			case "namespace":
				e.identity.Namespace = e.identity.Host
			case "no-identity":
				e.identity = nil
			case "dns":
				o.Desired.Config.DNS = networkplan.DNS{Mode: "dhcp", InterfaceID: "wan"}
				o.Desired, _ = networkplan.Canonical(o.Desired.Config)
			}
			count := k.mutations
			if _, err := newLeaseExecutor(context.Background(), e, o, func() (int64, error) { return *now, nil }); err == nil || k.mutations != count {
				t.Fatal("unsupported adoption", err)
			}
		})
	}
}

func TestLeaseExecutorWrongFactsNeverApply(t *testing.T) {
	for _, kind := range []string{"owner", "boot", "pid", "start", "sequence", "desired", "binding", "overlap", "gateway", "expiry", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			l, k, f, now := leaseFixture(t)
			switch kind {
			case "owner":
				f.Owner.Incarnation = strings.Repeat("c", 32)
			case "boot":
				f.Owner.BootID = strings.Repeat("0", 36)
			case "pid":
				f.Owner.PID++
			case "start":
				f.Owner.StartTicks++
			case "sequence":
				f.Sequence = 0
			case "desired":
				f.DesiredHash = strings.Repeat("f", 64)
			case "binding":
				f.WAN.HardwareAddress = "02:00:00:00:00:ff"
			case "overlap":
				f.Address = "198.18.0.10/24"
				f.Gateway = "198.18.0.2"
			case "gateway":
				f.Gateway = "203.0.113.1"
			case "expiry":
				f.DeadlineBootNS = *now
			case "revoked":
				f.Revoked = true
				f.Address = ""
				f.Gateway = ""
				f.DeadlineBootNS = 0
			}
			if _, err := l.Refresh(context.Background()); err == nil || k.mutations != 0 {
				t.Fatal("invalid lease applied", err)
			}
		})
	}
}

func TestLeaseExecutorChangedLeaseNeverResurrectsOldTuple(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "partial-error"}[failure], func(t *testing.T) {
			l, k, f, _ := leaseFixture(t)
			if _, err := l.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.Sequence++
			f.Address = "198.19.0.9/24"
			if failure {
				k.failAt = k.mutations + 4
				k.afterEffect = true
			}
			out, err := l.Refresh(context.Background())
			if failure {
				if err == nil || out != LeaseWANWithdrawn || l.base.active != nil {
					t.Fatal("false rollback to invalid old lease", out, err)
				}
				o, _ := l.base.observe(context.Background())
				if !reflect.DeepEqual(o, l.baseline) {
					t.Fatal("WAN not withdrawn")
				}
			} else {
				if err != nil || out != LeaseApplied || l.Verify(context.Background()) != nil {
					t.Fatal(out, err)
				}
				if k.state.Links[1].Addresses[0].Local != "198.19.0.9" {
					t.Fatal("old lease retained")
				}
			}
		})
	}
}

func TestLeaseExecutorExpiryRevocationAndOwnerLossWithdraw(t *testing.T) {
	for _, kind := range []string{"expiry", "revoked", "owner-loss"} {
		t.Run(kind, func(t *testing.T) {
			l, k, f, now := leaseFixture(t)
			if _, err := l.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "expiry":
				*now = f.DeadlineBootNS
			case "revoked":
				f.Sequence++
				f.Revoked = true
				f.Address = ""
				f.Gateway = ""
				f.DeadlineBootNS = 0
			case "owner-loss":
				l.current = func(context.Context) (LeaseFact, error) { return LeaseFact{}, ErrScope }
			}
			count := k.mutations
			if l.Verify(context.Background()) == nil || k.mutations != count {
				t.Fatal("Verify accepted expired evidence or mutated")
			}
			out, err := l.Refresh(context.Background())
			if !errors.Is(err, ErrLeaseUnavailable) || out != LeaseWANWithdrawn {
				t.Fatal(out, err)
			}
			o, _ := l.base.observe(context.Background())
			if !reflect.DeepEqual(o, l.baseline) {
				t.Fatal("expiry failed to preserve LAN")
			}
		})
	}
}

func TestLeaseExecutorEveryPartialFailureCompensates(t *testing.T) {
	for n := 1; n <= 2; n++ {
		for _, after := range []bool{false, true} {
			l, k, _, _ := leaseFixture(t)
			k.failAt = n
			k.afterEffect = after
			out, err := l.Refresh(context.Background())
			if err == nil || out != LeaseBaselineRestored || l.base.fenced || l.base.active != nil {
				t.Fatal(n, after, out, err)
			}
			o, _ := l.base.observe(context.Background())
			if !reflect.DeepEqual(o, l.baseline) {
				t.Fatal("partial effects retained")
			}
		}
	}
}

func TestLeaseExecutorLANDriftFencesBeforeFurtherEffects(t *testing.T) {
	for _, active := range []bool{false, true} {
		l, k, f, _ := leaseFixture(t)
		if active {
			if _, err := l.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.Sequence++
		}
		k.state.Links[0].Addresses[0].Local = "198.18.0.99"
		count := k.mutations
		out, err := l.Refresh(context.Background())
		if out != LeaseFenced || !errors.Is(err, ErrUncertain) || k.mutations != count {
			t.Fatal(out, err)
		}
		if _, err = l.Withdraw(context.Background()); !errors.Is(err, ErrUncertain) || k.mutations != count {
			t.Fatal("fence reopened")
		}
	}
}

func TestLeaseExecutorChangeDuringApplyAndRollbackFailure(t *testing.T) {
	l, k, f, _ := leaseFixture(t)
	prior := l.base.run
	l.base.run = func(ctx context.Context, op operation) ([]byte, error) {
		b, err := prior(ctx, op)
		if op.kind == "address-add" {
			f.Sequence++
			f.Revoked = true
			f.Address = ""
			f.Gateway = ""
			f.DeadlineBootNS = 0
		}
		return b, err
	}
	if out, err := l.Refresh(context.Background()); err == nil || out != LeaseBaselineRestored || k.mutations != 2 {
		t.Fatal(out, err, k.mutations)
	}
	l, k, _, _ = leaseFixture(t)
	k.failAt = 2
	k.afterEffect = true
	k.failDelete = true
	if out, err := l.Refresh(context.Background()); out != LeaseFenced || !errors.Is(err, ErrUncertain) {
		t.Fatal(out, err)
	}
}

func TestLeaseRulesCommandIsReadOnly(t *testing.T) {
	a, err := arguments(operation{kind: "rules"})
	if err != nil || !reflect.DeepEqual(a, []string{"-4", "-j", "rule", "show"}) {
		t.Fatal(a, err)
	}
}

func TestLeaseConstructorRejectsChangingReadbackWithoutEffects(t *testing.T) {
	e, k, o, _, now := leaseInputs(t)
	prior := e.run
	reads := 0
	e.run = func(ctx context.Context, op operation) ([]byte, error) {
		if op.kind == "addresses" {
			reads++
			if reads == 2 {
				k.state.Links[0].Addresses[0].Local = "198.18.0.99"
			}
		}
		return prior(ctx, op)
	}
	if _, err := newLeaseExecutor(context.Background(), e, o, func() (int64, error) { return *now, nil }); err == nil || k.mutations != 0 {
		t.Fatal("unstable baseline accepted or changed", err)
	}
}

func TestLeaseConstructorDetachesDesiredConfiguration(t *testing.T) {
	e, k, o, _, now := leaseInputs(t)
	l, err := newLeaseExecutor(context.Background(), e, o, func() (int64, error) { return *now, nil })
	if err != nil {
		t.Fatal(err)
	}
	o.Desired.Config.Interfaces[1].Binding.Name = "foreign0"
	o.Desired.Config.Zones[0].ID = "foreign"
	if out, err := l.Refresh(context.Background()); err != nil || out != LeaseApplied || k.mutations != 2 {
		t.Fatal("caller mutation reached retained configuration", out, err)
	}
}

func TestLeaseCanceledRequestCompensatesWithManagerLifetime(t *testing.T) {
	l, k, _, _ := leaseFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prior := l.base.run
	l.base.run = func(ctx context.Context, op operation) ([]byte, error) {
		b, err := prior(ctx, op)
		if op.kind == "address-add" {
			cancel()
		}
		return b, err
	}
	out, err := l.Refresh(ctx)
	if err == nil || out != LeaseBaselineRestored || k.mutations != 2 || l.base.active != nil {
		t.Fatal("request cancellation stranded an owned delta", out, err, k.mutations)
	}
}

func TestLeaseReplayCannotExtendInstalledDeadline(t *testing.T) {
	l, k, f, now := leaseFixture(t)
	if _, err := l.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	*now = f.DeadlineBootNS
	f.DeadlineBootNS += int64(time.Hour)
	out, err := l.Refresh(context.Background())
	if !errors.Is(err, ErrLeaseUnavailable) || out != LeaseWANWithdrawn || l.base.active != nil || k.mutations != 4 {
		t.Fatal("replayed sequence extended expired installed state", out, err)
	}
}

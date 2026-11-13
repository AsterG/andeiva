//go:build linux

package configpoc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
)

type dhcpAuthorityFixtureV3 struct {
	grant         RoutedDHCPGrantV3
	state         networkexecutor.LeaseSelectedStateV3
	denied        bool
	changed       bool
	ownerDead     bool
	withdrawCalls int
}

func (a *dhcpAuthorityFixtureV3) Current(context.Context) (RoutedDHCPGrantV3, error) {
	if a.denied || a.ownerDead {
		return RoutedDHCPGrantV3{}, ErrRecovery
	}
	return clone(a.grant), nil
}
func (a *dhcpAuthorityFixtureV3) WithdrawSelected(_ context.Context, ref SelectionReferenceV2) error {
	if !validHash(ref.WorkHash) || ref.Mode != "dhcp-recovery" {
		return ErrRecovery
	}
	a.withdrawCalls++
	a.state = networkexecutor.LeaseSelectedBaselineV3
	return nil
}
func (a *dhcpAuthorityFixtureV3) VerifyClosed(_ context.Context, s networkexecutor.LeaseSelectedSnapshotV3, state networkexecutor.LeaseSelectedStateV3) error {
	if a.denied || state != a.state || s.Identity != a.grant.Snapshot.Identity {
		return ErrRecovery
	}
	if a.changed {
		a.grant.Epoch++
	}
	return nil
}

func dhcpSnapshotFixtureV3(t *testing.T) networkexecutor.LeaseSelectedSnapshotV3 {
	t.Helper()
	doc, objects := compositeRoutedFixture(t, true)
	n := objects[doc.Domains.Firewall.Revision].Config.Routed.Network.Config
	n.Interfaces[1].IPv4 = networkplan.IPv4{Mode: "dhcp"}
	network, err := networkplan.Canonical(n)
	if err != nil {
		t.Fatal(err)
	}
	s := networkexecutor.LeaseSelectedSnapshotV3{Version: 3, Identity: networkexecutor.OwnedNamespaceIdentity{UID: 1001, GID: 1002, Namespace: 200, Host: 100, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}, Desired: network, OwnerPID: 50, OwnerStartTicks: 12345, OwnerIncarnation: strings.Repeat("b", 32), Sequence: 1, DeadlineBootNS: int64(240 * time.Second), WANIndex: 2, WAN: network.Config.Interfaces[1].Binding, Address: "198.19.0.1/24", Gateway: "198.19.0.2", Metric: 10, RouteTable: "main", RouteProtocol: "static",
		Links: []networkexecutor.SnapshotLink{
			{Index: 1, Name: "lan0", MAC: "02:00:00:00:01:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{{Family: "inet", Local: "198.18.0.1", Bits: 24, Scope: "global", Label: "lan0", Valid: 4294967295, Preferred: 4294967295}}},
			{Index: 2, Name: "wan0", MAC: "02:00:00:00:02:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}},
		}, Routes: []networkexecutor.SnapshotRoute{
			{Destination: "198.18.0.1", Device: "lan0", Protocol: "kernel", Scope: "host", Source: "198.18.0.1", Table: "local", Type: "local"},
			{Destination: "198.18.0.0/24", Device: "lan0", Protocol: "kernel", Scope: "link", Source: "198.18.0.1", Table: "main", Type: "unicast"},
		}}
	slices.SortFunc(s.Routes, func(a, b networkexecutor.SnapshotRoute) int {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return bytes.Compare(x, y)
	})
	_, s.Hash, err = v2Canonical(s)
	if err != nil {
		t.Fatal(err)
	}
	s, err = networkexecutor.CanonicalLeaseSelectedSnapshotV3(s)
	if err != nil {
		t.Fatal("snapshot", err)
	}
	return s
}

func dhcpStoreFixtureV3(t *testing.T) (*RoutedDHCPSelectedStoreV3, *dhcpAuthorityFixtureV3) {
	t.Helper()
	c, _, _ := routedCoordinatorFixtureV2(t)
	snap := dhcpSnapshotFixtureV3(t)
	doc, objects := compositeRoutedFixture(t, true)
	fw := objects[doc.Domains.Firewall.Revision].Config
	fw.Routed.Network = snap.Desired
	firewall, err := CanonicalRouted(fw)
	if err != nil {
		t.Fatal(err)
	}
	st := clone(c.store.state)
	st.Configuration.Firewall.Running, st.Configuration.Firewall.Startup, st.Configuration.Firewall.LastGood = firewall, firewall, firewall
	if _, err := c.store.object(firewall); err != nil {
		t.Fatal(err)
	}
	if err := st.Configuration.refresh(); err != nil {
		t.Fatal(err)
	}
	if err := c.store.publish(st); err != nil {
		t.Fatal("fixture selection", err)
	}
	manager := c.store.reserves
	c.store = sharedTestStoreV2(t, c.store)
	c.store.reserves = manager
	a := &dhcpAuthorityFixtureV3{grant: RoutedDHCPGrantV3{Epoch: 1, Snapshot: snap}, state: networkexecutor.LeaseSelectedBaselineV3}
	boot := v2BootID(snap.Identity.BootID)
	c.options.BootID = &boot
	c.options.RoutedIdentity = snap.Identity
	w, err := NewRoutedDHCPSelectedStoreV3(&ServiceV2{coordinator: c}, snap.Identity, a)
	if err != nil {
		t.Fatal(err)
	}
	return w, a
}

func TestRoutedDHCPSelectedV3LifecycleArchiveAndReplay(t *testing.T) {
	w, a := dhcpStoreFixtureV3(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		hash, err := w.Prepare(ctx)
		if err != nil {
			t.Fatal("prepare", i, err)
		}
		s := w.c.store
		if !hasFeatureV2(s.state, v3RoutedDHCPFeature) || s.state.RoutedDHCP.Phase != "prepared" || s.reserves.verifySelected(s) != nil {
			t.Fatal("selected R2 not verified")
		}
		if err := w.Applied(ctx, hash); err == nil {
			t.Fatal("baseline accepted as target")
		}
		a.state = networkexecutor.LeaseSelectedTargetV3
		if err := w.Applied(ctx, hash); err != nil {
			t.Fatal("applied", err)
		}
		if err := w.Withdrawn(ctx, hash); err == nil {
			t.Fatal("target accepted as withdrawn")
		}
		a.state = networkexecutor.LeaseSelectedBaselineV3
		if err := w.Withdrawn(ctx, hash); err != nil {
			t.Fatal("withdrawn", err)
		}
		if s.state.RoutedDHCP != nil || s.state.RoutedDHCPLast == "" || s.state.ReservedBytes != 0 || s.reserves.verifySelected(s) != nil {
			t.Fatal("archive/reserve release")
		}
		if _, err := w.Prepare(ctx); err == nil {
			t.Fatal("same grant revived")
		}
		a.grant.Epoch++
		a.grant.Snapshot.Sequence++
		a.grant.Snapshot.DeadlineBootNS += int64(time.Second)
		a.grant.Snapshot.Hash = ""
		_, a.grant.Snapshot.Hash, err = v2Canonical(a.grant.Snapshot)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestRoutedDHCPSelectedV3AuthorityChangeNoPublication(t *testing.T) {
	w, a := dhcpStoreFixtureV3(t)
	before := w.c.store.selector
	a.changed = true
	if _, err := w.Prepare(context.Background()); err == nil || w.c.store.selector != before || w.c.store.state.RoutedDHCP != nil {
		t.Fatal("authority change selected")
	}
}

func TestRoutedDHCPSelectedV3NoStaticSerializationChange(t *testing.T) {
	st := v2State{}
	b, _, err := v2Canonical(st)
	if err != nil || strings.Contains(string(b), "dhcp") {
		t.Fatal("static state bytes changed")
	}
	in := v2CoordinatorIntent{}
	b, _, err = v2Canonical(in)
	if err != nil || strings.Contains(string(b), "dhcp") {
		t.Fatal("static intent bytes changed")
	}
	w, a := dhcpStoreFixtureV3(t)
	before := clone(*w.c.store.state.Configuration)
	hash, err := w.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after := clone(*w.c.store.state.Configuration)
	if after.AuditSequence != before.AuditSequence+1 {
		t.Fatal("missing prepare audit")
	}
	after.AuditSequence, after.AuditTip = before.AuditSequence, before.AuditTip
	if !reflect.DeepEqual(before, after) {
		t.Fatal("DHCP changed desired configuration")
	}
	a.denied = true
	if !errors.Is(w.Applied(context.Background(), hash), ErrRecovery) {
		t.Fatal("owner loss accepted")
	}
}

func TestRoutedDHCPSelectedV3RecoveryWithdrawsDeadOwnerAndRejectsNewBoot(t *testing.T) {
	for _, mode := range []string{"same-scope", "new-boot", "no-proof", "missing-capability"} {
		t.Run(mode, func(t *testing.T) {
			w, a := dhcpStoreFixtureV3(t)
			hash, err := w.Prepare(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			a.state = networkexecutor.LeaseSelectedTargetV3
			if err = w.Applied(context.Background(), hash); err != nil {
				t.Fatal(err)
			}
			a.ownerDead = true
			w.c.options.DHCPRecovery = a
			switch mode {
			case "new-boot":
				boot := v2BootID("cccccccc-cccc-cccc-cccc-cccccccccccc")
				w.c.options.BootID = &boot
			case "no-proof":
				a.denied = true
			case "missing-capability":
				w.c.options.DHCPRecovery = nil
			}
			err = w.c.recoverRoutedDHCPAtOpenV3(context.Background())
			if mode == "same-scope" {
				if err != nil || a.withdrawCalls != 1 || w.c.store.state.RoutedDHCP != nil || w.c.store.state.RoutedDHCPLast == "" {
					t.Fatal("recovery", err)
				}
			} else if err == nil || w.c.store.state.RoutedDHCP == nil {
				t.Fatal("unproved recovery accepted")
			}
			if (mode == "new-boot" || mode == "missing-capability") && a.withdrawCalls != 0 {
				t.Fatal("foreign recovery effects")
			}
		})
	}
}

func TestRoutedDHCPSelectedV3RejectsDroppingOrReversingSelectedPhase(t *testing.T) {
	w, a := dhcpStoreFixtureV3(t)
	hash, err := w.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before := clone(w.c.store.state)
	bad := clone(before)
	bad.RoutedDHCP = nil
	if preservesFeaturesV2(before, bad) {
		t.Fatal("prepared reserve erased")
	}
	bad = clone(before)
	bad.RoutedDHCP.Work = strings.Repeat("f", 64)
	if preservesFeaturesV2(before, bad) {
		t.Fatal("work replaced in place")
	}
	a.state = networkexecutor.LeaseSelectedTargetV3
	if err = w.Applied(context.Background(), hash); err != nil {
		t.Fatal(err)
	}
	if preservesFeaturesV2(w.c.store.state, before) {
		t.Fatal("phase rolled back")
	}
	a.state = networkexecutor.LeaseSelectedBaselineV3
	if err = w.Withdrawn(context.Background(), hash); err != nil {
		t.Fatal(err)
	}
	before = clone(w.c.store.state)
	bad = clone(before)
	bad.RoutedDHCPLast = ""
	if preservesFeaturesV2(before, bad) {
		t.Fatal("anti-replay witness erased")
	}
}

func TestRoutedDHCPSelectedV3BindsPhysicalPlanAndContext(t *testing.T) {
	w, _ := dhcpStoreFixtureV3(t)
	if _, err := w.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	original := clone(w.c.store.state)
	for _, kind := range []string{"work", "phase", "generation", "wall-clock", "intent", "binding", "feature"} {
		t.Run(kind, func(t *testing.T) {
			bad := clone(original)
			switch kind {
			case "work":
				bad.RoutedDHCP.Work = strings.Repeat("f", 64)
			case "phase":
				bad.RoutedDHCP.Phase = "restored"
			case "generation":
				bad.Generation++
			case "wall-clock":
				bad.RoutedDHCP.Bundle.Scope.Deadline = time.Now().UTC()
			case "intent":
				bad.RoutedDHCP.Bundle.PlanIntent.DHCPWork = strings.Repeat("f", 64)
			case "binding":
				bad.RoutedDHCP.Bundle.Plan.Digest = strings.Repeat("f", 64)
			case "feature":
				kept := []string{}
				for _, f := range bad.RequiredFeatures {
					if f != v3RoutedDHCPFeature {
						kept = append(kept, f)
					}
				}
				bad.RequiredFeatures = kept
			}
			if validateRoutedDHCPSelectedV3(bad, w.c.store.readObject) == nil && w.c.store.reserves.verifyBundle(w.c.store, bad.RoutedDHCP.Bundle) == nil {
				t.Fatal("altered selected work accepted")
			}
		})
	}
}

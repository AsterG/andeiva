//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
)

type routedLinksFixtureV3 struct {
	l         *RoutedGatewayLinksV3
	parents   [2]routedLinkObservationV3
	links     []routedLinkObservationV3
	ops       []routedLinkOperationV3
	intercept func(routedLinkOperationV3) error
}

func newRoutedLinksFixtureV3(t *testing.T) *routedLinksFixtureV3 {
	t.Helper()
	f := &routedLinksFixtureV3{links: []routedLinkObservationV3{{Index: 1, Name: "lo", Flags: []string{"LOOPBACK"}}}}
	parents := [2]RoutedParentLinkV3{{2, "uplink-a", "02:11:22:33:44:55", 1500}, {3, "uplink-b", "02:11:22:33:44:56", 1500}}
	for i, p := range parents {
		f.parents[i] = routedLinkObservationV3{Index: p.Index, Name: p.Name, MAC: p.MAC, MTU: p.MTU, Flags: []string{"UP"}}
	}
	var err error
	f.l, err = newRoutedGatewayLinksV3(context.Background(), "0123456789abcdef0123456789abcdef", parents, func(ctx context.Context, op routedLinkOperationV3) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f.ops = append(f.ops, op)
		if f.intercept != nil {
			if err := f.intercept(op); err != nil {
				return nil, err
			}
		}
		switch op.kind {
		case "parent":
			return json.Marshal([]routedLinkObservationV3{f.parents[op.slot]})
		case "gateway":
			return json.Marshal(f.links)
		case "create":
			p := f.parents[op.slot]
			child := routedLinkObservationV3{Index: 10 + op.slot, Name: routedLinkNameV3(op.slot), MAC: f.l.macs[op.slot], MTU: p.MTU, Parent: p.Index}
			child.Info.Kind = "macvlan"
			child.Info.Data.Mode = "private"
			f.links = append(f.links, child)
			return nil, nil
		case "remove":
			f.links = slices.DeleteFunc(f.links, func(v routedLinkObservationV3) bool { return v.Name == routedLinkNameV3(op.slot) })
			return nil, nil
		default:
			t.Fatal("unexpected operation", op)
			return nil, ErrConfiguration
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRoutedGatewayLinksV3OwnedLifecycle(t *testing.T) {
	f := newRoutedLinksFixtureV3(t)
	if err := f.l.Create(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.links) != 3 || f.l.created[0] == nil || f.l.created[1] == nil {
		t.Fatal("missing readback ownership")
	}
	if err := f.l.Create(context.Background()); err == nil {
		t.Fatal("duplicate create")
	}
	// Runtime link-up is legitimate; cleanup still checks immutable ownership.
	f.links[1].Flags = []string{"UP"}
	if err := f.l.Close(); err != nil {
		t.Fatal(err)
	}
	if len(f.links) != 1 || f.links[0].Name != "lo" {
		t.Fatal("foreign link changed")
	}
	n := len(f.ops)
	if f.l.Close() != nil || len(f.ops) != n {
		t.Fatal("close not idempotent")
	}
	for _, op := range f.ops {
		program, args, err := f.l.arguments(op)
		if err != nil || (program != "/usr/sbin/ip" && program != "/usr/bin/nsenter") {
			t.Fatal("unbounded executable")
		}
		for _, a := range args {
			if a == "up" || a == "route" || a == "addr" || a == "forwarding" {
				t.Fatal("L3 effect", args)
			}
		}
	}
}

func TestRoutedGatewayLinksV3RejectsForeignOrChangedLinks(t *testing.T) {
	for _, which := range []string{"foreign-gateway", "parent-index", "parent-mac", "parent-mtu", "parent-promiscuity", "parent-down"} {
		t.Run(which, func(t *testing.T) {
			f := newRoutedLinksFixtureV3(t)
			switch which {
			case "foreign-gateway":
				f.links = append(f.links, routedLinkObservationV3{Index: 99, Name: "foreign"})
			case "parent-index":
				f.parents[0].Index++
			case "parent-mac":
				f.parents[0].MAC = "02:aa:aa:aa:aa:aa"
			case "parent-mtu":
				f.parents[0].MTU--
			case "parent-promiscuity":
				f.parents[0].Promiscuity = 1
			case "parent-down":
				f.parents[0].Flags = nil
			}
			if f.l.Create(context.Background()) == nil {
				t.Fatal("foreign binding accepted")
			}
			for _, op := range f.ops {
				if op.kind == "create" || op.kind == "remove" {
					t.Fatal("mutated unowned namespace")
				}
			}
		})
	}
}

func TestRoutedGatewayLinksV3CleanupDoesNotDeleteReplacements(t *testing.T) {
	for _, which := range []string{"index", "mac", "parent", "mode", "missing"} {
		t.Run(which, func(t *testing.T) {
			f := newRoutedLinksFixtureV3(t)
			if f.l.Create(context.Background()) != nil {
				t.Fatal("create")
			}
			switch which {
			case "index":
				f.links[2].Index++
			case "mac":
				f.links[2].MAC = "02:aa:aa:aa:aa:aa"
			case "parent":
				f.links[2].Parent++
			case "mode":
				f.links[2].Info.Data.Mode = "bridge"
			case "missing":
				f.links = f.links[:2]
			}
			before := len(f.ops)
			if f.l.Close() == nil {
				t.Fatal("foreign replacement treated as clean")
			}
			for _, op := range f.ops[before:] {
				if op.kind == "remove" && op.slot == 1 {
					t.Fatal("removed unproved identity")
				}
			}
		})
	}
}

func TestRoutedGatewayLinksV3UncertainCreateRetainsFence(t *testing.T) {
	f := newRoutedLinksFixtureV3(t)
	f.intercept = func(op routedLinkOperationV3) error {
		if op.kind == "create" && op.slot == 1 {
			return errors.New("lost acknowledgment")
		}
		return nil
	}
	if f.l.Create(context.Background()) == nil || !f.l.uncertain {
		t.Fatal("lost acknowledgment not fenced")
	}
	if f.l.Create(context.Background()) == nil {
		t.Fatal("uncertain retry")
	}
	if f.l.Close() == nil {
		t.Fatal("unproven full cleanup")
	}
	if len(f.links) != 1 {
		t.Fatal("known first child not removed")
	}
}

func TestRoutedGatewayLinksV3Boundary(t *testing.T) {
	f := newRoutedLinksFixtureV3(t)
	for _, name := range []string{"", "lo", "../eth0", "eth0;true", "eth0\n", "@x", "-x/"} {
		p := f.l.parents[0]
		p.Name = name
		if validRoutedParentV3(p) {
			t.Fatal("bad name accepted", name)
		}
	}
	if _, _, err := f.l.arguments(routedLinkOperationV3{kind: "shell"}); err == nil {
		t.Fatal("unknown operation")
	}
	if _, _, err := f.l.arguments(routedLinkOperationV3{kind: "create", slot: 2}); err == nil {
		t.Fatal("unbounded slot")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f.l.Create(ctx) == nil || len(f.ops) != 0 {
		t.Fatal("cancelled creation effects")
	}
	file, err := os.CreateTemp(t.TempDir(), "namespace-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if routedLinkNamespaceV3(file, 1) {
		t.Fatal("ordinary file namespace")
	}
}

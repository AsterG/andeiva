package localchannel

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/locallistener"
	"github.com/AsterG/andeiva/internal/localobserve"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

type bindingWorker struct {
	worker
	bindings []localpolicy.Listener
}

func (w *bindingWorker) Registry() (locallistener.Registry, error) {
	return locallistener.Registry{Hash: w.hash, Bindings: w.bindings}, nil
}

func TestJoinedObservationRequiresActualSocketIdentity(t *testing.T) {
	for _, scenario := range []string{"valid", "missing", "wrong_uid", "wildcard", "mapped", "udp", "foreign", "wrong_port", "wrong_family", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			inventory := []localpolicy.Interface{{Name: "src0", Zone: localpolicy.LAN, Addresses: []string{"198.18.1.1"}}}
			service, err := localpolicy.DefaultManagement("management", "https", inventory[0], "198.18.1.1", []string{"198.18.1.2/32"})
			if err != nil {
				t.Fatal(err)
			}
			service.Endpoints = []localpolicy.Endpoint{{Protocol: localpolicy.TCP, FirstPort: 18080, LastPort: 18080}}
			local := localpolicy.Config{SchemaVersion: 1, Interfaces: inventory, Services: []localpolicy.Service{service}}
			revision, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &local})
			if err != nil {
				t.Fatal(err)
			}
			binding := testBinding()
			socket := localobserve.Socket{Protocol: "tcp", Family: "ipv4", Address: "198.18.1.1", Port: 18080, Inode: 77, UID: binding.UID}
			snapshot := localobserve.Snapshot{RunID: binding.Run, Instance: binding.Instance, Generation: binding.Generation, Namespace: binding.Namespace, StartTime: 5, Sockets: []localobserve.Socket{socket}}
			switch scenario {
			case "missing":
				snapshot.Sockets = nil
			case "wrong_uid":
				snapshot.Sockets[0].UID++
			case "wildcard":
				snapshot.Sockets[0].Wildcard = true
			case "mapped":
				snapshot.Sockets[0].Mapped = true
			case "udp":
				snapshot.Sockets[0].Protocol = "udp"
			case "foreign":
				snapshot.Foreign = []localobserve.Socket{socket}
			case "wrong_port":
				snapshot.Sockets[0].Port++
			case "wrong_family":
				snapshot.Sockets[0].Family = "ipv6"
			case "duplicate":
				snapshot.Sockets = append(snapshot.Sockets, socket)
			}
			w := &bindingWorker{bindings: []localpolicy.Listener{{Owner: "management", Service: "https", Interface: "src0", LocalAddress: "198.18.1.1", Protocol: localpolicy.TCP, Port: 18080}}}
			a, b := net.Pipe()
			c, d := net.Pipe()
			defer a.Close()
			defer b.Close()
			defer c.Close()
			defer d.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			go func() { _ = Serve(ctx, b, binding, w, nil) }()
			go func() { _ = Serve(ctx, d, binding, nil, collector{snapshot}) }()
			wc, err := New(a, binding, false)
			if err != nil {
				t.Fatal(err)
			}
			oc, err := New(c, binding, true)
			if err != nil {
				t.Fatal(err)
			}
			joined, err := NewListeners(wc, oc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = joined.Observe(ctx); err == nil {
				t.Fatal("observation before activation")
			}
			if err = joined.Apply(ctx, revision); err != nil {
				t.Fatal(err)
			}
			got, err := joined.Observe(ctx)
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("socket identity result %v: %v", got, err)
			}
			if err == nil && len(got) != 1 {
				t.Fatal(got)
			}
		})
	}
}

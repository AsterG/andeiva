package localpolicy

import (
	"encoding/json"
	"errors"
	"testing"
)

func matchingObservation(t *testing.T, c Config) Observation {
	t.Helper()
	a, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	o := Observation{Revision: a.Revision.Hash, Rules: a.Rules}
	for _, s := range a.Revision.Config.Services {
		if !s.Enabled {
			continue
		}
		for _, b := range s.Bindings {
			for _, e := range s.Endpoints {
				for port := e.FirstPort; ; port++ {
					o.Listeners = append(o.Listeners, Listener{s.Owner, s.ID, b.Interface, b.LocalAddress, e.Protocol, port})
					if port == e.LastPort {
						break
					}
				}
			}
		}
	}
	return o
}

func TestReconcileProvidedObservations(t *testing.T) {
	c := fixture()
	o := matchingObservation(t, c)
	r, err := Reconcile(c, o)
	if err != nil || !r.Consistent {
		t.Fatal(r, err)
	}
	cases := map[string]func(*Observation){
		"revision_mismatch":   func(o *Observation) { o.Revision = "stale" },
		"missing_listener":    func(o *Observation) { o.Listeners = nil },
		"missing_rule":        func(o *Observation) { o.Rules = nil },
		"duplicate_listener":  func(o *Observation) { o.Listeners = append(o.Listeners, o.Listeners[0]) },
		"duplicate_rule":      func(o *Observation) { o.Rules = append(o.Rules, o.Rules[0]) },
		"unexpected_listener": func(o *Observation) { o.Listeners[0].LocalAddress = "0.0.0.0" },
		"unexpected_rule":     func(o *Observation) { o.Rules[0].ID = "foreign" },
		"rule_mismatch":       func(o *Observation) { o.Rules[0].Owner = "different-owner" },
	}
	for code, change := range cases {
		t.Run(code, func(t *testing.T) {
			o := matchingObservation(t, c)
			change(&o)
			r, err := Reconcile(c, o)
			if err != nil || r.Consistent {
				t.Fatal("unexpected match", r, err)
			}
			found := false
			for _, d := range r.Differences {
				found = found || d.Code == code
			}
			if !found {
				t.Fatal("missing diagnostic", code, r)
			}
		})
	}
}

func TestRejectPartialRulesStalePortsAndDisabledResiduals(t *testing.T) {
	c := fixture()
	c.Services[0].Bindings = append(c.Services[0].Bindings, Binding{Interface: "lan0", Zone: LAN, LocalAddress: "2001:db8:1::1", Sources: []string{"2001:db8:1::10/128"}})
	o := matchingObservation(t, c)
	o.Rules = o.Rules[:1]
	r, err := Reconcile(c, o)
	if err != nil || r.Consistent {
		t.Fatal("partial rules accepted", r, err)
	}
	o = matchingObservation(t, c)
	c.Services[0].Endpoints[0] = Endpoint{TCP, 8443, 8443}
	a, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	o.Revision = a.Revision.Hash
	r, err = Reconcile(c, o)
	if err != nil || r.Consistent {
		t.Fatal("old port residual accepted", r, err)
	}
	c.Services[0].Enabled = false
	a, err = Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	o.Revision = a.Revision.Hash
	r, err = Reconcile(c, o)
	if err != nil || r.Consistent {
		t.Fatal("disabled residual accepted", r, err)
	}
	o = Observation{Revision: a.Revision.Hash}
	r, err = Reconcile(c, o)
	if err != nil || !r.Consistent {
		t.Fatal("zero-exclusive-rules state mismatch", r, err)
	}
	o.Listeners = make([]Listener, maxListeners+1)
	if _, err = Reconcile(c, o); !errors.Is(err, ErrPolicy) {
		t.Fatal("unbounded observation accepted")
	}
}

func TestLastPortDoesNotOverflow(t *testing.T) {
	c := fixture()
	c.Services[0].Endpoints = []Endpoint{{TCP, 65534, 65535}}
	o := matchingObservation(t, c)
	r, err := Reconcile(c, o)
	if err != nil || !r.Consistent || len(o.Listeners) != 2 {
		t.Fatal("last-port observation", r, err)
	}
}

func TestDeclaredSnapshotsRemainIndependent(t *testing.T) {
	startup := fixture()
	running := cloneConfig(t, startup)
	running.Services[0].Endpoints[0] = Endpoint{TCP, 8443, 8443}
	candidate := cloneConfig(t, running)
	candidate.Services[0].Enabled = false
	for _, c := range []Config{startup, running, candidate} {
		a, err := Compile(c)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(a.Revision.Config)
		if err != nil {
			t.Fatal(err)
		}
		r, err := Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Compile(r.Config)
		if err != nil || a.Digest != b.Digest {
			t.Fatal("serialized declaration changed compile result", err)
		}
	}
	if startup.Services[0].Endpoints[0].FirstPort != 443 || running.Services[0].Endpoints[0].FirstPort != 8443 || !running.Services[0].Enabled || candidate.Services[0].Enabled {
		t.Fatal("declaration mutation crossed snapshots")
	}
	// These are independent values only. Real transactional publication, restart
	// recovery, commit-confirmed deadlines and audit require the future bridge.
}

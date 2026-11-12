package routednft

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/AsterG/andeiva/internal/nftengine"
)

func observation(batch []byte) []byte {
	var v struct {
		Objects []object `json:"nftables"`
	}
	_ = json.Unmarshal(batch, &v)
	entries := []object{}
	for _, o := range v.Objects {
		if add, ok := o["add"].(map[string]any); ok {
			entries = append(entries, add)
		}
	}
	data, _ := json.Marshal(object{"nftables": entries})
	return data
}
func TestCanonicalRejectsUnsafePolicy(t *testing.T) {
	cases := []func(*Policy){
		func(p *Policy) { p.Rules[0].Enabled = nil },
		func(p *Policy) { p.LabOnly = false }, func(p *Policy) { p.RequireIdentification = true }, func(p *Policy) { p.RequireInspection = true },
		func(p *Policy) { p.Rules[0].Protocol = "icmp" }, func(p *Policy) { p.Rules[0].Protocol = "all" }, func(p *Policy) { p.Rules[0].SourcePorts.From = 0 },
		func(p *Policy) { p.Rules[0].Destination = "::/0" }, func(p *Policy) { p.Rules[0].Source = "1.2.3.4; accept" }, func(p *Policy) { p.Rules[0].Path.FromZone = "outside" },
		func(p *Policy) { p.Rules[0].Path.ToInterface = "missing" }, func(p *Policy) { p.Network.Hash = "untrusted" },
		func(p *Policy) { p.NAT[0].Source = "0.0.0.0/0" }, func(p *Policy) { p.NAT[0].Path.FromInterface = "wan" }, func(p *Policy) { p.Rules = append(p.Rules, p.Rules[0]) },
	}
	for i, change := range cases {
		p := LabPolicy()
		change(&p)
		if _, e := Compile(p); e == nil {
			t.Fatalf("accepted %d", i)
		}
	}
	p := LabPolicy()
	p.Rules[0].Source = "198.18.0.123/24"
	r, e := Canonical(p)
	if e != nil || r.Policy.Rules[0].Source != "198.18.0.0/24" {
		t.Fatal("canonical prefix")
	}
}

func TestExplicitStateAndLegacyIdentifiers(t *testing.T) {
	p := LabPolicy()
	p.Rules[0].ID = "Legacy.Rule-01_" + strings.Repeat("x", 49)
	if len(p.Rules[0].ID) != 64 {
		t.Fatal("invalid test ID")
	}
	active, e := Compile(p)
	if e != nil {
		t.Fatal(e)
	}
	*p.Rules[0].Enabled = false
	disabled, e := Compile(p)
	if e != nil {
		t.Fatal(e)
	}
	if disabled.Revision.Hash == active.Revision.Hash || len(disabled.Revision.Policy.Rules) != 2 || disabled.Revision.Policy.Rules[0].IsEnabled() {
		t.Fatal("inactive configuration lost")
	}
	if !active.Revision.Policy.Rules[0].IsEnabled() {
		t.Fatal("enabled pointer aliases caller")
	}
	if strings.Contains(string(disabled.Create), p.Rules[0].ID+":") {
		t.Fatal("inactive kernel rule")
	}
	o, e := VerifyObservation(observation(disabled.Create), disabled.Revision)
	if e != nil || len(o.Counters) != 8 {
		t.Fatal("inactive counters", e, len(o.Counters))
	}
	if _, e = VerifyObservation(observation(active.Create), disabled.Revision); e == nil {
		t.Fatal("stale active readback accepted")
	}
	if _, e = VerifyObservation(observation(disabled.Create), active.Revision); e == nil {
		t.Fatal("unobserved disable accepted")
	}
	changed := p
	changed.Rules = append([]Rule{}, p.Rules...)
	changed.Rules[0].Destination = "203.0.113.9/32"
	r, e := Canonical(changed)
	if e != nil || r.Hash == disabled.Revision.Hash {
		t.Fatal("inactive edit absent from revision")
	}
	p.Rules[0].ID += "x"
	if _, e = Compile(p); e == nil {
		t.Fatal("oversized ID")
	}
	p = LabPolicy()
	*p.Rules[0].Enabled = false
	p.Rules[0].Protocol = "unsupported"
	if _, e = Compile(p); e == nil {
		t.Fatal("inactive invalid rule bypassed validation")
	}
}

func TestOrderedCurrentPolicyReadback(t *testing.T) {
	p := LabPolicy()
	base, e := Compile(p)
	if e != nil {
		t.Fatal(e)
	}
	p.Rules[0], p.Rules[1] = p.Rules[1], p.Rules[0]
	reordered, e := Compile(p)
	if e != nil {
		t.Fatal(e)
	}
	if base.Revision.Hash == reordered.Revision.Hash {
		t.Fatal("reorder lost")
	}
	if _, e = VerifyObservation(observation(base.Create), reordered.Revision); e == nil {
		t.Fatal("old ordering accepted")
	}
	unknown := strings.Replace(string(observation(base.Create)), `tcp-test:original:allow`, `unknown:original:allow`, 1)
	if _, e = VerifyObservation([]byte(unknown), base.Revision); e == nil {
		t.Fatal("unknown kernel policy ID")
	}
	p.Rules[0].Action = "deny"
	deny, e := Compile(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyObservation(observation(reordered.Create), deny.Revision); e == nil {
		t.Fatal("old allow accepted after deny")
	}
}

func TestICMPTypesUseExactSetMembership(t *testing.T) {
	a, e := Compile(LabPolicy())
	if e != nil {
		t.Fatal(e)
	}
	data := observation(a.Create)
	if !strings.Contains(string(data), `"right":{"set":[3,11,12]}`) {
		t.Fatal("missing exact ICMP error set")
	}
	for _, bad := range []string{`"right":[3,11,12]`, `"right":{"set":[3,5,11,12]}`, `"right":{"set":[0,3,11,12]}`, `"right":{"set":[3,11]}`} {
		modified := strings.Replace(string(data), `"right":{"set":[3,11,12]}`, bad, 1)
		if _, e := VerifyObservation([]byte(modified), a.Revision); e == nil {
			t.Fatal("accepted broadened or malformed ICMP set", bad)
		}
	}
}

func TestNativeICMPReadbackRetainsEveryPredicate(t *testing.T) {
	// Transcribed from the orchestrator's actual nft 1.1.3 readback; only the
	// admission mark is rebound to this test's explicitly-enabled revision.
	const recorded = `{"rule":{"family":"inet","table":"andeiva_routed_alpha","chain":"forward","comment":"tcp-test:original:related","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lan0"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"wan0"}},{"match":{"op":"==","left":{"ct":{"key":"direction"}},"right":0}},{"match":{"op":"==","left":{"ct":{"key":"ip saddr","dir":"original"}},"right":{"prefix":{"addr":"198.18.0.0","len":24}}}},{"match":{"op":"==","left":{"ct":{"key":"ip daddr","dir":"original"}},"right":"198.19.0.2"}},{"match":{"op":"==","left":{"ct":{"key":"protocol"}},"right":6}},{"match":{"op":"==","left":{"ct":{"key":"proto-src","dir":"original"}},"right":{"range":[1024,65535]}}},{"match":{"op":"==","left":{"ct":{"key":"proto-dst","dir":"original"}},"right":18080}},{"match":{"op":"==","left":{"ct":{"key":"state"}},"right":4}},{"match":{"op":"==","left":{"ct":{"key":"mark"}},"right":@MARK@}},{"match":{"op":"==","left":{"payload":{"protocol":"icmp","field":"type"}},"right":{"set":[3,11,12]}}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}}`
	p := LabPolicy()
	r, _ := Canonical(p)
	var expected object
	for _, o := range policyObjects(r) {
		if b, ok := o["rule"].(object); ok && b["comment"] == "tcp-test:original:related" {
			expected = o
		}
	}
	data := strings.ReplaceAll(recorded, "@MARK@", strconv.FormatUint(uint64(ruleMark(p.Rules[0])), 10))
	var actual object
	_ = json.Unmarshal([]byte(data), &actual)
	if !sameObject(actual, expected) {
		t.Fatal("actual native ICMP grammar rejected")
	}
	for _, change := range [][2]string{{`"ip saddr"`, `"saddr"`}, {`"198.18.0.0"`, `"0.198.18.0"`}, {`"len":24`, `"len":16`}, {`"right":6`, `"right":17`}, {`"right":4`, `"right":2`}, {`"set":[3,11,12]`, `"set":[3,5,11,12]`}, {`"dir":"original"`, `"dir":"reply"`}} {
		var bad object
		_ = json.Unmarshal([]byte(strings.Replace(data, change[0], change[1], 1)), &bad)
		if sameObject(bad, expected) {
			t.Fatal("native drift accepted", change)
		}
	}
}
func TestSemanticReadback(t *testing.T) {
	a, e := Compile(LabPolicy())
	if e != nil {
		t.Fatal(e)
	}
	data := observation(a.Create)
	o, e := VerifyObservation(data, a.Revision)
	if e != nil || len(o.Counters) != 14 {
		t.Fatalf("readback %v counters %d", e, len(o.Counters))
	}
	for _, pair := range [][2]string{{`"policy":"drop"`, `"policy":"accept"`}, {`"prio":100`, `"prio":99`}, {`"key":"mark"`, `"key":"id"`}, {`"dir":"original"`, `"dir":"reply"`}, {`"masquerade":null`, `"accept":null`}, {`"key":"iifname"`, `"key":"oifname"`}, {`"related"`, `"untracked"`}, {`"proto-dst"`, `"proto-src"`}} {
		changed := []byte(strings.Replace(string(data), pair[0], pair[1], 1))
		if string(changed) == string(data) {
			t.Fatal("bad test mutation", pair)
		}
		if _, e := VerifyObservation(changed, a.Revision); e == nil {
			t.Fatal("accepted drift", pair)
		}
	}
	// Real counter movement and kernel handles do not change authorization.
	changed := strings.ReplaceAll(string(data), `"packets":0`, `"packets":32`)
	changed = strings.Replace(changed, `"name":"`+TableName+`"`, `"handle":19,"name":"`+TableName+`"`, 1)
	if _, e := VerifyObservation([]byte(changed), a.Revision); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifyObservation([]byte(`{"nftables":[],"nftables":[]}`), a.Revision); e == nil {
		t.Fatal("duplicate keys")
	}
}
func TestCompileIsolationAndState(t *testing.T) {
	a, _ := Compile(LabPolicy())
	s := string(a.Batch)
	for _, bad := range []string{`"hook":"input"`, `"hook":"output"`, `"flush"`, `"key":"state"},"op":"in","right":["established","related"]`} {
		if strings.Contains(s, bad) {
			t.Fatal(bad)
		}
	}
	p := LabPolicy()
	p.NAT = nil
	noNAT, _ := Compile(p)
	if strings.Contains(string(noNAT.Batch), `"masquerade"`) {
		t.Fatal("unrequested NAT")
	}
	p = LabPolicy()
	p.Rules = nil
	natOnly, _ := Compile(p)
	if strings.Contains(string(natOnly.Batch), `"accept":null`) {
		t.Fatal("NAT authorized forwarding")
	}
	p = LabPolicy()
	p.Rules[0].Action = "deny"
	deny, _ := Compile(p)
	if strings.Contains(string(deny.Batch), `tcp-test:reply:allow`) {
		t.Fatal("deny became reply allow")
	}
}

type fakeTransport struct {
	data                              []byte
	checkFails, ackLost, observeFails bool
	loseReadback                      bool
	checks, applies                   int
}

func (f *fakeTransport) Check(context.Context, []byte) error {
	f.checks++
	if f.checkFails {
		return errors.New("check")
	}
	return nil
}
func (f *fakeTransport) Apply(_ context.Context, b []byte) error {
	f.applies++
	f.data = observation(b)
	f.observeFails = f.loseReadback
	if f.ackLost {
		return errors.New("ack")
	}
	return nil
}
func (f *fakeTransport) Observe(context.Context) ([]byte, error) {
	if f.observeFails {
		return nil, errors.New("read")
	}
	return append([]byte{}, f.data...), nil
}
func TestAdapterLostAcknowledgementAndConcurrency(t *testing.T) {
	base, _ := Compile(LabPolicy())
	p := LabPolicy()
	p.NAT = nil
	target, _ := Compile(p)
	f := &fakeTransport{data: observation(base.Create), ackLost: true}
	a, _ := NewAdapter(f, base.Revision)
	if e := a.Apply(context.Background(), target.Revision); !errors.Is(e, nftengine.ErrTransport) {
		t.Fatal(e)
	}
	if o, e := a.Inspect(context.Background()); e != nil || o.Revision.Hash != target.Revision.Hash {
		t.Fatal("lost ack not reconciled", e)
	}
	f.ackLost = false
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := a.Apply(context.Background(), base.Revision); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if f.applies != 2 || f.checks != 2 {
		t.Fatal("nonserialized no-op", f.applies, f.checks)
	}
	f.data = []byte(strings.Replace(string(f.data), `"policy":"drop"`, `"policy":"accept"`, 1))
	if e := a.Apply(context.Background(), target.Revision); !errors.Is(e, nftengine.ErrDrift) || f.applies != 2 {
		t.Fatal("drift changed state", e)
	}
}
func TestAdapterCheckFailure(t *testing.T) {
	base, _ := Compile(LabPolicy())
	p := LabPolicy()
	p.NAT = nil
	target, _ := Compile(p)
	f := &fakeTransport{data: observation(base.Create), checkFails: true}
	a, _ := NewAdapter(f, base.Revision)
	if e := a.Apply(context.Background(), target.Revision); !errors.Is(e, nftengine.ErrTransport) || f.applies != 0 {
		t.Fatal(e)
	}
}

func TestAdapterLostReadbackOnlyAdmitsAuthorizedOutcome(t *testing.T) {
	base, _ := Compile(LabPolicy())
	p := LabPolicy()
	p.NAT = nil
	target, _ := Compile(p)
	f := &fakeTransport{data: observation(base.Create), loseReadback: true}
	a, _ := NewAdapter(f, base.Revision)
	if e := a.Apply(context.Background(), target.Revision); !errors.Is(e, nftengine.ErrTransport) {
		t.Fatal(e)
	}
	f.observeFails = false
	third := LabPolicy()
	third.Rules = nil
	unauthorized, _ := Compile(third)
	f.data = observation(unauthorized.Create)
	if _, e := a.Inspect(context.Background()); !errors.Is(e, nftengine.ErrDrift) {
		t.Fatal("unrelated outcome accepted", e)
	}
	f.data = observation(target.Create)
	if o, e := a.Inspect(context.Background()); e != nil || o.Revision.Hash != target.Revision.Hash {
		t.Fatal("authorized target not reconciled", e)
	}
}
func FuzzReadback(f *testing.F) {
	a, _ := Compile(LabPolicy())
	f.Add(observation(a.Create))
	f.Add([]byte(`{"nftables":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxObservation {
			t.Skip()
		}
		_, _ = VerifyObservation(data, a.Revision)
	})
}

func BenchmarkCompile(b *testing.B) {
	p := LabPolicy()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, e := Compile(p); e != nil {
			b.Fatal(e)
		}
	}
}
func BenchmarkVerify(b *testing.B) {
	a, _ := Compile(LabPolicy())
	data := observation(a.Create)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, e := VerifyObservation(data, a.Revision); e != nil {
			b.Fatal(e)
		}
	}
}

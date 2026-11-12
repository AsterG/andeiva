package firewallipc

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

func routedWireV3(t *testing.T, verb string, payload any) []byte {
	t.Helper()
	p, e := json.Marshal(payload)
	if e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(RoutedRequestV3{RoutedProtocolV3, strings.Repeat("a", 32), 7, 22, "routed", verb, p})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestRoutedCodecV3RequiresExactHandshake(t *testing.T) {
	h := NewRoutedHelloV3(strings.Repeat("a", 32), 22)
	data, _ := json.Marshal(h)
	if _, e := DecodeRoutedHelloV3(data, false); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*RoutedHelloV3){func(h *RoutedHelloV3) { h.ProtocolVersion = 2 }, func(h *RoutedHelloV3) { h.Domain = "firewall" }, func(h *RoutedHelloV3) { h.Namespace = 0 }, func(h *RoutedHelloV3) { h.RequiredFeatures = h.RequiredFeatures[:2] }, func(h *RoutedHelloV3) { h.RequiredFeatures[1] = "reader_profile.v2" }, func(h *RoutedHelloV3) { h.Run = strings.Repeat("b", 32) }} {
		v := NewRoutedHelloV3(strings.Repeat("a", 32), 22)
		mutate(&v)
		b, _ := json.Marshal(v)
		if _, e := DecodeRoutedHelloV3(b, false); e == nil {
			t.Fatalf("accepted incompatible hello: %s", b)
		}
	}
	h.Run = strings.Repeat("b", 32)
	h.Epoch = 1
	data, _ = json.Marshal(h)
	if _, e := DecodeRoutedHelloV3(data, true); e != nil {
		t.Fatal(e)
	}
}
func TestRoutedCodecV3RejectsManufacturedAuthorityAndReplay(t *testing.T) {
	ref := RoutedReferenceV3{strings.Repeat("b", 64), "v2.lineage.fixture", "18446744073709551615"}
	for _, verb := range []string{"arm", "apply", "confirm", "recover", "bootstrap", "resume", "match"} {
		p := RoutedSelectedV3{Reference: ref}
		if verb == "match" {
			p.Side = "before"
		}
		wire := routedWireV3(t, verb, p)
		r, c, e := DecodeRoutedRequestV3(wire, strings.Repeat("a", 32), 22, 6)
		if e != nil || r.Sequence != 7 || c.Reference != ref {
			t.Fatal(verb, e)
		}
		if _, _, e = DecodeRoutedRequestV3(wire, strings.Repeat("a", 32), 22, 7); e == nil {
			t.Fatal("replay accepted")
		}
		for _, change := range []struct{ old, new string }{{`"protocol_version":3`, `"protocol_version":2`}, {`"domain":"routed"`, `"domain":"firewall"`}, {`"namespace":22`, `"namespace":23`}, {`"generation":"18446744073709551615"`, `"generation":"01"`}, {`"generation":"18446744073709551615"`, `"generation":"18446744073709551616"`}, {`"work":"` + ref.Work + `"`, `"work":"not-a-hash"`}, {`"reference":{`, `"valid":true,"reference":{`}, {`"reference":{`, `"reference":{"command":"nft",`}} {
			bad := strings.Replace(string(wire), change.old, change.new, 1)
			if bad == string(wire) {
				t.Fatal("test mutation absent")
			}
			if _, _, e = DecodeRoutedRequestV3([]byte(bad), strings.Repeat("a", 32), 22, 6); e == nil {
				t.Fatalf("accepted %s", bad)
			}
		}
	}
	for _, raw := range []string{`{"path":"/etc/passwd"}`, `{"valid":true}`, `null`, `{"reference":{},"reference":{}}`} {
		if _, _, e := DecodeRoutedRequestV3(routedWireV3(t, "apply", json.RawMessage(raw)), strings.Repeat("a", 32), 22, 6); e == nil {
			t.Fatal(raw)
		}
	}
}
func TestRoutedCodecV3PreparationHasCanonicalDataOnly(t *testing.T) {
	fw, e := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny"})
	if e != nil {
		t.Fatal(e)
	}
	local, e := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1}})
	if e != nil {
		t.Fatal(e)
	}
	bundle, e := configpoc.NewRoutedActivationBundleV1(fw, local)
	if e != nil {
		t.Fatal(e)
	}
	for _, verb := range []string{"prepare", "prepare_boot"} {
		wire := routedWireV3(t, verb, RoutedPrepareV3{Target: bundle, Baseline: bundle.Composite.Hash})
		if _, _, e = DecodeRoutedRequestV3(wire, strings.Repeat("a", 32), 22, 6); e != nil {
			t.Fatal(e)
		}
		for _, key := range []string{"baseline", "identity", "ttl", "command", "path"} {
			bad := strings.Replace(string(wire), `"target":`, fmt.Sprintf(`"%s":{},"target":`, key), 1)
			if _, _, e = DecodeRoutedRequestV3([]byte(bad), strings.Repeat("a", 32), 22, 6); e == nil {
				t.Fatal(key)
			}
		}
	}
}

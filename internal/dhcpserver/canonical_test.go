package dhcpserver

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCanonicalIndependentAndStable(t *testing.T) {
	input, bindings := fixture()
	input.Scopes[0].Pools = []Pool{{"192.0.2.40", "192.0.2.50"}, {"192.0.2.10", "192.0.2.35"}}
	input.Scopes[0].Excluded = []string{"192.0.2.21", "192.0.2.20"}
	input.Scopes[0].DNS = []string{"192.0.2.2", "192.0.2.1"}
	original, _ := json.Marshal(input)
	got, err := Canonical(input, bindings)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Canonical(got, bindings)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("not idempotent", err)
	}
	after, _ := json.Marshal(input)
	if string(original) != string(after) || got.Scopes[0].DNS[0] != "192.0.2.2" {
		t.Fatal("mutated input or DNS priority")
	}
	input.Scopes[0].Pools[0].First = "changed"
	input.Scopes[0].Excluded[0] = "changed"
	input.Scopes[0].Reservations[0].MAC = "changed"
	input.Scopes[0].DNS[0] = "changed"
	input.Scopes[0].NTP[0] = "changed"
	after, _ = json.Marshal(got)
	before, _ := json.Marshal(again)
	if string(after) != string(before) {
		t.Fatal("aliased nested configuration")
	}
}

func TestCanonicalDisabledStillValidatesAndNormalizes(t *testing.T) {
	input, bindings := fixture()
	input.Enabled = false
	got, err := Canonical(input, bindings)
	if err != nil || got.Enabled || len(got.Scopes) != 1 {
		t.Fatal("disabled config lost", err)
	}
	input.Scopes[0].InterfaceID = "wan"
	if _, err = Canonical(input, bindings); err != ErrInvalid {
		t.Fatal("disabled bypass", err)
	}
	got, err = Canonical(Config{SchemaVersion: 1}, nil)
	if err != nil || got.Scopes == nil {
		t.Fatal("empty canonical", err)
	}
}

func BenchmarkCanonical(b *testing.B) {
	c, bindings := fixture()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Canonical(c, bindings); err != nil {
			b.Fatal(err)
		}
	}
}

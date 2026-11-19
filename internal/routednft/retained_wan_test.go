package routednft

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/AsterG/andeiva/internal/networkplan"
)

func retainedRuleExpressions(t *testing.T, raw []byte, comment string) []byte {
	t.Helper()
	var envelope struct {
		Objects []struct {
			Rule struct {
				Comment string          `json:"comment"`
				Expr    json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	for _, entry := range envelope.Objects {
		if entry.Rule.Comment == comment {
			return entry.Rule.Expr
		}
	}
	t.Fatalf("missing rule %s", comment)
	return nil
}

func TestRetainedWANRequiresCurrentMarkInBothDirections(t *testing.T) {
	policy := LabPolicy()
	legacy, err := Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileRetainedWANChange(legacy.Revision, legacy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	observed := observation(compiled.Create)
	if _, err := VerifyRetainedWANObservation(observed, compiled.Revision); err != nil {
		t.Fatal("retained WAN readback", err)
	}
	if _, err := VerifyObservation(observed, legacy.Revision); err == nil {
		t.Fatal("legacy verifier accepted a different enforcement profile")
	}
	if _, err := VerifyRetainedWANObservation(observation(legacy.Create), compiled.Revision); err == nil {
		t.Fatal("retained WAN verifier accepted legacy enforcement")
	}

	mark := ruleMark(policy.Rules[0])
	markMatch := fmt.Sprintf(`"left":{"ct":{"key":"mark"}},"op":"==","right":%d`, mark)
	for _, direction := range []string{"original", "reply"} {
		name := "tcp-test:" + direction + ":allow"
		fields := retainedRuleExpressions(t, observed, name)
		if !bytes.Contains(fields, []byte(markMatch)) || bytes.Contains(fields, []byte("mangle")) {
			t.Fatalf("%s did not require the current established mark", name)
		}
	}
	newConnection := retainedRuleExpressions(t, observed, "tcp-test:original:new")
	if !bytes.Contains(newConnection, []byte(`"right":"new"`)) || !bytes.Contains(newConnection, []byte(fmt.Sprintf(`"mangle":{"key":{"ct":{"key":"mark"}},"value":%d}`, mark))) {
		t.Fatal("new flow did not receive the exact current mark")
	}
	if !bytes.Contains(newConnection, []byte(`"\u0026":[{"payload":{"field":"flags","protocol":"tcp"}},23]},"op":"==","right":2`)) {
		t.Fatal("a midstream packet could regain admission without a fresh SYN")
	}
	// Preserve the rejected entry's identity until the helper can retire it.
	denied := retainedRuleExpressions(t, observed, "tcp-test:original:unadmitted")
	if bytes.Contains(denied, []byte("mangle")) || !bytes.Contains(denied, []byte(`"drop":null`)) {
		t.Fatal("rejected traffic can alter the identity of an entry due for retirement")
	}
}

func TestRetainedWANRuleOrderingKeepsConnectionIdentity(t *testing.T) {
	policy := LabPolicy()
	initial := ruleMark(policy.Rules[0])
	policy.Rules[0], policy.Rules[1] = policy.Rules[1], policy.Rules[0]
	if got := ruleMark(policy.Rules[1]); got != initial {
		t.Fatal("reordering changed the admission mark")
	}
	policy.Rules[1].ID = "changed-tcp"
	if got := ruleMark(policy.Rules[1]); got == initial {
		t.Fatal("fixture does not exercise replacement of admission identity")
	}
}

func TestRetainedWANChangeRefusesDifferentNetworkOrNAT(t *testing.T) {
	policy := LabPolicy()
	before, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.NAT = nil
	changed, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompileRetainedWANChange(before, changed); err == nil {
		t.Fatal("atomic policy branch admitted a NAT change")
	}
	policy = before.Policy
	policy.Network.Config.DefaultRoute.Metric++
	policy.Network, err = networkplan.Canonical(policy.Network.Config)
	if err != nil {
		t.Fatal(err)
	}
	changed, err = Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompileRetainedWANChange(before, changed); err == nil {
		t.Fatal("atomic policy branch admitted a different network revision")
	}
	foreign := before
	foreign.Hash = changed.Hash
	if _, err := CompileRetainedWANChange(before, foreign); err == nil {
		t.Fatal("atomic policy branch accepted an unverified revision")
	}
}

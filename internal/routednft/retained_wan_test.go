package routednft

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

func initialMarks(t *testing.T, revision Revision) routedmodel.AdmissionMarks {
	t.Helper()
	marks, _, err := routedmodel.ReserveAdmissionMarks("8eecf0f0-b75e-4ba4-ae71-1dff6749bd44", 0, nil, Revision{}, revision)
	if err != nil {
		t.Fatal(err)
	}
	return marks
}

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
	assigned := initialMarks(t, legacy.Revision)
	compiled, err := CompileMarkedPolicy(legacy.Revision, assigned)
	if err != nil {
		t.Fatal(err)
	}
	observed := observation(compiled.Create)
	if _, err := VerifyRetainedWANObservation(observed, compiled.Revision, assigned); err != nil {
		t.Fatal("retained WAN readback", err)
	}
	if _, err := VerifyObservation(observed, legacy.Revision); err == nil {
		t.Fatal("legacy verifier accepted a different enforcement profile")
	}
	if _, err := VerifyRetainedWANObservation(observation(legacy.Create), compiled.Revision, assigned); err == nil {
		t.Fatal("retained WAN verifier accepted legacy enforcement")
	}

	mark := assigned.Bindings[0].Mark
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
	if !bytes.Contains(newConnection, []byte(`"left":{"ct":{"key":"mark"}},"op":"==","right":0`)) {
		t.Fatal("a pending entry could receive a different mark during retirement")
	}
	retransmit := retainedRuleExpressions(t, observed, "tcp-test:original:new-admitted")
	if !bytes.Contains(retransmit, []byte(markMatch)) || bytes.Contains(retransmit, []byte("mangle")) {
		t.Fatal("a retransmit did not retain its original identity")
	}
	// Preserve the rejected entry's identity until the helper can retire it.
	denied := retainedRuleExpressions(t, observed, "tcp-test:original:unadmitted")
	if bytes.Contains(denied, []byte("mangle")) || !bytes.Contains(denied, []byte(`"drop":null`)) {
		t.Fatal("rejected traffic can alter the identity of an entry due for retirement")
	}
}

func TestRetainedWANRuleOrderingKeepsConnectionIdentity(t *testing.T) {
	policy := LabPolicy()
	before, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	initial := initialMarks(t, before)
	policy.Rules[0], policy.Rules[1] = policy.Rules[1], policy.Rules[0]
	target, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	_, reordered, err := CompileRetainedWANChange(before, target, initial, initial.Issued)
	if err != nil || reordered.Bindings[1] != initial.Bindings[0] {
		t.Fatal("reordering changed the admission mark")
	}
	policy.Rules[1].ID = "changed-tcp"
	target, err = Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	_, changed, err := CompileRetainedWANChange(before, target, initial, initial.Issued)
	if err != nil || changed.Bindings[1].Mark <= initial.Bindings[0].Mark {
		t.Fatal("rename did not allocate a fresh admission mark", err)
	}
}

func TestRetainedWANChangeRefusesDifferentNetworkOrNAT(t *testing.T) {
	policy := LabPolicy()
	before, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	marks := initialMarks(t, before)
	policy.NAT = nil
	changed, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := CompileRetainedWANChange(before, changed, marks, marks.Issued); err == nil {
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
	if _, _, err := CompileRetainedWANChange(before, changed, marks, marks.Issued); err == nil {
		t.Fatal("atomic policy branch admitted a different network revision")
	}
	foreign := before
	foreign.Hash = changed.Hash
	if _, _, err := CompileRetainedWANChange(before, foreign, marks, marks.Issued); err == nil {
		t.Fatal("atomic policy branch accepted an unverified revision")
	}
}

func TestRetainedWANRestoreRejectsRetiredMarks(t *testing.T) {
	policy := LabPolicy()
	original, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	initial := initialMarks(t, original)
	policy.Rules[0].Action = "deny"
	denied, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	_, changed, err := CompileRetainedWANChange(original, denied, initial, initial.Issued)
	if err != nil {
		t.Fatal(err)
	}
	artifact, restored, err := CompileRetainedWANChange(denied, original, changed, changed.Issued+1)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Bindings[0].Mark <= initial.Bindings[0].Mark || restored.Bindings[1] != initial.Bindings[1] ||
		restored.Issued != changed.Issued+2 {
		t.Fatal("restoration reused a retired or reserved mark", restored)
	}
	observed := observation(artifact.Create)
	if _, err = VerifyRetainedWANObservation(observed, original, restored); err != nil {
		t.Fatal(err)
	}
	old := []byte(fmt.Sprint(initial.Bindings[0].Mark))
	current := []byte(fmt.Sprint(restored.Bindings[0].Mark))
	if bytes.Contains(observed, old) {
		t.Fatal("retired admission mark is present in loaded rules")
	}
	if _, err = VerifyRetainedWANObservation(bytes.Replace(observed, current, old, 1), original, restored); err == nil {
		t.Fatal("readback accepted a retired admission mark")
	}
}

func TestRetainedWANRequiresClosureWhenRuleCoverageChanges(t *testing.T) {
	policy := LabPolicy()
	before, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	initial := initialMarks(t, before)
	block := before.Policy.Rules[0]
	block.ID, block.Action, block.Source = "partial-block", "deny", "198.18.0.2/32"
	policy.Rules = append([]Rule{block}, policy.Rules...)
	target, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := CompileRetainedWANChange(before, target, initial, initial.Issued); err == nil {
		t.Fatal("atomic path retained identity when an earlier rule changed its coverage")
	}
	guarded, needsClosure, err := routedmodel.ReserveAdmissionMarks(initial.Boot, initial.Issued, &initial, before, target)
	if err != nil || !needsClosure || guarded.Bindings[0].Mark == initial.Bindings[0].Mark ||
		guarded.Bindings[1] != initial.Bindings[1] {
		t.Fatal("guarded path failed to retire only the changed coverage", guarded, err)
	}
}

func TestRetainedWANMarkExhaustionAndRestartWatermark(t *testing.T) {
	before, err := Canonical(LabPolicy())
	if err != nil {
		t.Fatal(err)
	}
	initial := initialMarks(t, before)
	if _, _, err := CompileRetainedWANChange(before, before, initial, initial.Issued-1); err == nil {
		t.Fatal("mark watermark moved backwards")
	}
	policy := LabPolicy()
	policy.Rules[0].ID = "tcp-replacement"
	changed, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	_, reserved, err := CompileRetainedWANChange(before, changed, initial, routedmodel.MaxAdmissionMarks-1)
	if err != nil || reserved.Issued != routedmodel.MaxAdmissionMarks {
		t.Fatal("failed to allocate the last mark", reserved, err)
	}
	if artifact, _, err := CompileRetainedWANChange(changed, before, reserved, reserved.Issued); !errors.Is(err, routedmodel.ErrAdmissionMarksExhausted) || len(artifact.Batch) != 0 {
		t.Fatal("exhausted boot allocated or compiled a recycled mark", err)
	}
}

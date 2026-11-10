package firewallnft

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func stateConfig(enabled bool) configpoc.Config {
	c := testConfig()
	c.SchemaVersion = 4
	c.Rules[0].Enabled = &enabled
	return c
}

func TestDisabledRulesRequireFullRevisionReadback(t *testing.T) {
	c := stateConfig(false)
	a, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	data := observed(t, c)
	if bytes.Contains(a.Batch, []byte(`"rule"`)) || !bytes.Contains(a.Batch, []byte(`"policy":"drop"`)) {
		t.Fatal("disabled rule became effective")
	}
	if _, err = InspectObservation(data); err == nil {
		t.Fatal("kernel comment reconstructed absent config")
	}
	o, err := VerifyObservation(data, a.Revision)
	if err != nil || o.Revision.Hash != a.Revision.Hash || len(o.Rules) != 0 {
		t.Fatal("trusted readback", err)
	}
	c.Rules[0].Match.DestinationPorts = configpoc.PortRange{From: 18443, To: 18443}
	other, _ := Compile(c)
	if _, err = VerifyObservation(data, other.Revision); err == nil {
		t.Fatal("different inactive config accepted")
	}
	c = stateConfig(true)
	active, _ := Compile(c)
	for _, bad := range [][]byte{observed(t, c), bytes.Replace(data, []byte(`"policy":"drop"`), []byte(`"policy":"accept"`), 1), bytes.Replace(data, []byte(a.Revision.Hash), []byte(active.Revision.Hash), 1)} {
		if _, err = VerifyObservation(bad, a.Revision); err == nil {
			t.Fatal("unexpected effective policy accepted")
		}
	}
}

func TestDisabledRulesRetainOrderedSelectorsAndRevokeReplies(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		c := stateConfig(true)
		c.Rules[0].Match.Protocol = protocol
		p := packet{"198.18.0.2", "198.18.0.6", protocol, "src0", "dst0", "original", "new", 35000, 18080, 0}
		allowed, mark := evaluate(t, c, p)
		if !allowed || mark != AdmittedMark {
			t.Fatal("positive control")
		}
		deny := c.Rules[0]
		deny.ID = "deny-first"
		deny.Action = "deny"
		enabled := false
		deny.Enabled = &enabled
		c.Rules = append([]configpoc.Rule{deny}, c.Rules...)
		if allowed, _ = evaluate(t, c, p); !allowed {
			t.Fatal("disabled deny became effective")
		}
		enabled = true
		if allowed, _ = evaluate(t, c, p); allowed {
			t.Fatal("first deny ignored")
		}
		c.Rules[0], c.Rules[1] = c.Rules[1], c.Rules[0]
		if allowed, _ = evaluate(t, c, p); !allowed {
			t.Fatal("array order ignored")
		}
		*c.Rules[0].Enabled = false
		p.direction = "reply"
		p.state = "established"
		p.mark = mark
		p.source, p.destination = p.destination, p.source
		p.input, p.output = p.output, p.input
		p.sport, p.dport = p.dport, p.sport
		if allowed, _ = evaluate(t, c, p); allowed {
			t.Fatal("disabled allow retained established reply")
		}
	}
}

type stateTransport struct {
	data                  []byte
	failApply, unreadable bool
	loseRead              bool
	applies               int
}

func (t *stateTransport) Check(context.Context, []byte) error { return nil }
func (t *stateTransport) Observe(context.Context) ([]byte, error) {
	if t.unreadable {
		return nil, errors.New("observation lost")
	}
	return bytes.Clone(t.data), nil
}
func (t *stateTransport) Apply(_ context.Context, b []byte) error {
	t.applies++
	var batch struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(b, &batch) != nil {
		return errors.New("batch")
	}
	objects := []json.RawMessage{}
	for _, command := range batch.Objects {
		if raw, ok := command["add"]; ok {
			objects = append(objects, raw)
		}
	}
	t.data, _ = json.Marshal(map[string]any{"nftables": objects})
	if t.loseRead {
		t.unreadable = true
	}
	if t.failApply {
		return errors.New("lost apply acknowledgement")
	}
	return nil
}

func TestUnknownApplyOutcomeOnlyAllowsKnownCompensation(t *testing.T) {
	transport := &stateTransport{data: observed(t, DefaultConfig())}
	engine := New(transport)
	base, _ := Compile(DefaultConfig())
	target, _ := Compile(stateConfig(false))
	foreign, _ := Compile(stateConfig(true))
	if engine.Current() != base.Revision.Hash {
		t.Fatal("baseline")
	}
	transport.loseRead = true
	if engine.Apply(context.Background(), target.Revision) == nil || engine.Current() != "" {
		t.Fatal("unknown outcome reported success")
	}
	count := transport.applies
	if engine.Apply(context.Background(), foreign.Revision) == nil || transport.applies != count {
		t.Fatal("uncertain state admitted unrelated target")
	}
	transport.loseRead = false
	transport.unreadable = false
	if err := engine.Apply(context.Background(), base.Revision); err != nil || engine.Current() != base.Revision.Hash {
		t.Fatal("authorized compensation failed", err)
	}
}

func TestLegacyDefaultKernelBatchGolden(t *testing.T) {
	const configJSON = `{"schema_version":2,"default_action":"deny","rules":[]}`
	sum := sha256.Sum256([]byte(configJSON))
	hash := hex.EncodeToString(sum[:])
	want := fmt.Sprintf(`{"nftables":[{"delete":{"table":{"family":"inet","name":"andeiva_admin"}}},{"add":{"table":{"comment":"andeiva.nft.admin.v2:%s","family":"inet","name":"andeiva_admin"}}},{"add":{"chain":{"family":"inet","hook":"forward","name":"forward","policy":"drop","prio":0,"table":"andeiva_admin","type":"filter"}}}]}`, hash)
	a, err := Compile(DefaultConfig())
	if err != nil || a.Revision.Hash != hash || string(a.Batch) != want {
		t.Fatal("legacy compiler bytes changed", err)
	}
}

func TestEngineRetainsTrustedInactivePolicyAcrossUncertainApply(t *testing.T) {
	transport := &stateTransport{data: observed(t, DefaultConfig())}
	engine := New(transport)
	base, _ := Compile(DefaultConfig())
	target, _ := Compile(stateConfig(false))
	if engine.Current() != base.Revision.Hash {
		t.Fatal("legacy bootstrap")
	}
	transport.failApply = true
	if engine.Apply(context.Background(), target.Revision) == nil {
		t.Fatal("lost acknowledgement accepted")
	}
	if engine.Current() != target.Revision.Hash {
		t.Fatal("known applied target not verified")
	}
	o, err := engine.Inspect(context.Background())
	if err != nil || len(o.Rules) != 0 || len(o.Revision.Config.Rules) != 1 {
		t.Fatal("inactive metadata lost", err)
	}
	*o.Revision.Config.Rules[0].Enabled = true
	if engine.Current() != target.Revision.Hash {
		t.Fatal("readback aliases retained revision")
	}
	transport.failApply = false
	if engine.Apply(context.Background(), base.Revision) != nil {
		t.Fatal("compensation to legacy failed")
	}
	foreign, _ := Compile(stateConfig(true))
	transport.data = observed(t, foreign.Revision.Config)
	if engine.Current() != "" {
		t.Fatal("foreign state accepted")
	}
	transport.data = observed(t, stateConfig(false))
	fresh := New(transport)
	if fresh.Current() != "" {
		t.Fatal("unknown schema4 kernel state adopted without journal")
	}
}

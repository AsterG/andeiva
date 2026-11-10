package previewruntime

import (
	"context"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

type localSessionEngine struct{ hash string }

func (e *localSessionEngine) Apply(_ context.Context, r configpoc.Revision) error {
	e.hash = r.Hash
	return nil
}
func (e *localSessionEngine) Current() string { return e.hash }

func TestLocalSessionKeepsRecoveryAndDomainGuards(t *testing.T) {
	inventory := []localpolicy.Interface{{Name: "src0", Zone: localpolicy.LAN, Addresses: []string{"198.18.1.1"}}}
	local := localpolicy.Config{SchemaVersion: 1, Interfaces: inventory}
	r, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &local})
	if err != nil {
		t.Fatal(err)
	}
	compile := func(c configpoc.Config) (string, error) {
		if c.LocalServices == nil || len(c.Rules) != 0 || c.DefaultAction != "deny" {
			return "", errHelper
		}
		a, err := localnft.Compile(*c.LocalServices)
		return a.Digest, err
	}
	a, err := localnft.Compile(local)
	if err != nil {
		t.Fatal(err)
	}
	e := &localSessionEngine{}
	g := nftguardian.NewRestricted(e)
	defer g.Close()
	s, err := NewLocalSession(strings.Repeat("a", 32), 42, e, g, compile, func(context.Context) (string, localpolicy.Observation, error) {
		return e.hash, localpolicy.Observation{Revision: a.Revision.Hash, Rules: a.Rules}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	seq := uint64(1) << 32
	call := func(m firewallipc.Message) firewallipc.Reply {
		t.Helper()
		seq++
		m.Run = s.run
		m.Sequence = seq
		reply, err := s.Handle(context.Background(), m)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	if reply := call(firewallipc.Message{Verb: "bootstrap", Revision: r}); reply.Error != "" || reply.Artifact != a.Digest {
		t.Fatal(reply)
	}
	if reply := call(firewallipc.Message{Verb: "recovered"}); reply.Error != "" {
		t.Fatal(reply)
	}
	if reply := call(firewallipc.Message{Verb: "observe"}); reply.Error != "" || reply.Local == nil || reply.Local.Revision != a.Revision.Hash || reply.Hash != r.Hash || len(reply.Counters) != 0 || reply.CounterEpoch != "" {
		t.Fatal(reply)
	}
	// A second bootstrap cannot overwrite the recovered runtime.
	if reply := call(firewallipc.Message{Verb: "bootstrap", Revision: r}); reply.Error == "" {
		t.Fatal("second bootstrap accepted")
	}
	forward, _ := configpoc.Canonical(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny"})
	_, err = s.Handle(context.Background(), firewallipc.Message{Run: s.run, Sequence: seq + 1, Verb: "apply", Revision: forward})
	if err == nil {
		t.Fatal("other domain accepted")
	}
}

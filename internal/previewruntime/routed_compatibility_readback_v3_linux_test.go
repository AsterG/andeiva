//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/firewallnft"
)

type routedReadbackFixtureV3 struct {
	mu         sync.Mutex
	obs        firewallnft.Observation
	present    bool
	generation uint64
	err        error
	calls      int
}

func (f *routedReadbackFixtureV3) ObserveLegacy(ctx context.Context) (firewallnft.Observation, bool, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if ctx.Err() != nil {
		return firewallnft.Observation{}, false, 0, ctx.Err()
	}
	return f.obs, f.present, f.generation, f.err
}

func readbackSessionFixtureV3() (*SessionV2, *routedReadbackFixtureV3) {
	fixture := &routedReadbackFixtureV3{}
	return &SessionV2{base: &Session{run: strings.Repeat("b", 32), namespace: 42}, domain: "firewall", readOnly: true, routedReadback: fixture}, fixture
}

func TestRoutedReadbackV3ColdLegacyAndRoutedObservation(t *testing.T) {
	s, fixture := readbackSessionFixtureV3()
	c := dialSessionV2(t, s, nil)
	defer func() { c.stop() }()
	ctx := context.Background()
	cold := attachV2(t, c.client)
	if cold.Hash != "" || cold.State.Phase != "bootstrap" {
		t.Fatal("cold absence represented as applied policy", cold)
	}
	if _, err := c.client.Observe(ctx); err == nil {
		t.Fatal("absent legacy table produced counters")
	}
	// A protocol error deliberately closes its client; the next controller
	// must authenticate again rather than reusing the poisoned connection.
	c.stop()
	c = dialSessionV2(t, s, nil)
	r, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.obs, fixture.present, fixture.generation = firewallnft.Observation{Revision: r}, true, 1
	fixture.mu.Unlock()
	if err = c.client.AttachObserved(ctx, cold); err == nil {
		t.Fatal("old absence attached after real policy changed")
	}
	c.stop()
	c = dialSessionV2(t, s, nil)
	state := attachV2(t, c.client)
	if state.State.Phase != "idle" || state.State.ID != "" || state.Hash != r.Hash {
		t.Fatal("legacy readback inherited a group lease", state)
	}
	observed, err := c.client.Observe(ctx)
	if err != nil || observed.Hash != r.Hash || observed.CounterEpoch != strings.Repeat("b", 32)+".1" {
		t.Fatal("present legacy observation failed", err)
	}
	fixture.mu.Lock()
	fixture.obs, fixture.present, fixture.generation = firewallnft.Observation{}, false, 2
	fixture.mu.Unlock()
	if current := attachV2(t, c.client); current.State.Phase != "bootstrap" || current.Hash != "" {
		t.Fatal("routed legacy absence rejected", current)
	}
	fixture.mu.Lock()
	fixture.err = errors.New("kernel observation failed")
	fixture.mu.Unlock()
	if _, err = c.client.Snapshot(ctx); err == nil {
		t.Fatal("failed observation exposed as absence")
	}
}

func TestRoutedReadbackV3DeniesEffectsBeforeSourceAndRejectsEnvelope(t *testing.T) {
	for _, verb := range []string{"bootstrap", "apply", "arm", "arm_until", "apply_scoped", "confirm", "confirm_scoped", "recover_scoped"} {
		s, fixture := readbackSessionFixtureV3()
		s.active, s.attached, s.cold, s.epoch, s.last = true, true, true, 1, 1<<32
		request := firewallipc.RequestV2{ProtocolVersion: 2, Run: s.base.run, Namespace: 42, Domain: "firewall", Sequence: (1 << 32) + 1, Verb: verb}
		reply, err := s.handleV2(context.Background(), 1, request, firewallipc.CommandV2{})
		if err != nil || reply.Error == "" || fixture.calls != 0 {
			t.Fatal("effect reached readback provider", verb, err)
		}
	}
	for _, invalid := range []string{"run", "namespace", "epoch", "sequence"} {
		s, fixture := readbackSessionFixtureV3()
		s.active, s.epoch, s.last = true, 1, 1<<32
		request := firewallipc.RequestV2{ProtocolVersion: 2, Run: s.base.run, Namespace: 42, Domain: "firewall", Sequence: (1 << 32) + 1, Verb: "state"}
		epoch := uint64(1)
		switch invalid {
		case "run":
			request.Run = strings.Repeat("c", 32)
		case "namespace":
			request.Namespace++
		case "epoch":
			epoch++
		case "sequence":
			request.Sequence--
		}
		if _, err := s.handleV2(context.Background(), epoch, request, firewallipc.CommandV2{}); err == nil || fixture.calls != 0 {
			t.Fatal("invalid envelope reached provider", invalid, err)
		}
	}
}

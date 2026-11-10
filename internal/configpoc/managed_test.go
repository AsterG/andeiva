package configpoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestV1JournalRecordsUnchangedOnReopen(t *testing.T) {
	s, engines, dir := fixture(t, Options{})
	c := sample("legacy")
	invoke(t, s, OpStage, &c, 0)
	invoke(t, s, OpCommit, nil, 0)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	original := map[string]string{}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			original[e.Name()] = string(b)
		}
	}
	reopened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{Initial: &Config{SchemaVersion: 2, DefaultAction: "deny"}})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if status(t, reopened).Running.Config.SchemaVersion != 1 {
		t.Fatal("existing store reinitialized")
	}
	for name, want := range original {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != want {
			t.Fatalf("legacy record modified: %s", name)
		}
	}
}

func firewallSample() Config {
	return Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []Rule{{ID: "web", Action: "allow", Match: &Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: PortRange{1, 65535}, DestinationPorts: PortRange{18080, 18080}}}}}
}

func TestV1GoldenAndV2Canonical(t *testing.T) {
	const golden = `{"schema_version":1,"default_action":"deny","rules":[{"id":"one","action":"allow"}]}`
	r, err := Canonical(sample("one"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r.Config)
	sum := sha256.Sum256([]byte(golden))
	if string(b) != golden || r.Hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("v1 changed: %s", b)
	}
	c := firewallSample()
	r, err = Canonical(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Rules[0].Match.Source = "0.0.0.0/0"
	if r.Config.Rules[0].Match.Source != "198.18.0.2/32" {
		t.Fatal("aliased match")
	}
	for name, mutate := range map[string]func(*Config){
		"v1_match": func(c *Config) { c.SchemaVersion = 1 },
		"missing":  func(c *Config) { c.Rules[0].Match = nil },
		"unmasked": func(c *Config) { c.Rules[0].Match.Source = "198.18.0.2/24" },
		"ipv6":     func(c *Config) { c.Rules[0].Match.Source = "::1/128" },
		"host":     func(c *Config) { c.Rules[0].Match.Source = "198.18.0.2" },
		"zeroport": func(c *Config) { c.Rules[0].Match.SourcePorts.From = 0 },
		"range":    func(c *Config) { c.Rules[0].Match.DestinationPorts.From = 18081 },
		"protocol": func(c *Config) { c.Rules[0].Match.Protocol = "icmp" },
	} {
		t.Run(name, func(t *testing.T) {
			c := firewallSample()
			mutate(&c)
			if _, err := Canonical(c); err == nil {
				t.Fatal("accepted invalid")
			}
		})
	}
}

type testGuard struct {
	arms, confirms int
	fail           bool
	inspect        func()
}

func (g *testGuard) Arm(context.Context, string, Revision, Revision, time.Duration) error {
	g.arms++
	return nil
}
func (g *testGuard) Confirm(context.Context, string, string) error {
	g.confirms++
	if g.inspect != nil {
		g.inspect()
	}
	if g.fail {
		return ErrRecovery
	}
	return nil
}

func TestManagedAuthorizationAndConfirmationOrdering(t *testing.T) {
	c := firewallSample()
	s, engines, _ := fixture(t, Options{Initial: &c})
	g := &testGuard{}
	ctx := context.Background()
	initial := status(t, s)
	c.Rules[0].Action = "deny"
	staged := invoke(t, s, OpStage, &c, 0)
	for _, tc := range []struct {
		p Principal
		r Request
	}{
		{Principal{"viewer", RoleViewer}, Request{Operation: OpCommit, Key: "denied", ExpectedGeneration: staged.Generation}},
		{Principal{"other", RoleAdmin}, Request{Operation: OpCommit, Key: "other", ExpectedGeneration: staged.Generation}},
		{admin, Request{Operation: OpCommit, Key: "stale", ExpectedGeneration: 1}},
		{admin, Request{Operation: OpCommit, Key: "invalid", ExpectedGeneration: staged.Generation, Target: "bad"}},
	} {
		if _, err := s.ExecuteManaged(ctx, tc.p, API, tc.r, g); err == nil {
			t.Fatal("accepted invalid mutation")
		}
	}
	if g.arms != 0 || g.confirms != 0 {
		t.Fatal("unauthorized helper mutation")
	}
	g.inspect = func() {
		if s.state.Snapshot.Running.Hash != initial.Running.Hash {
			t.Fatal("published before authority")
		}
		if engines[0].Current() == initial.Running.Hash {
			t.Fatal("confirmed before apply")
		}
	}
	r, err := s.ExecuteManaged(ctx, admin, API, Request{Operation: OpCommit, Key: "normal", ExpectedGeneration: staged.Generation}, g)
	if err != nil || r.Pending != nil || g.arms != 1 || g.confirms != 1 {
		t.Fatalf("normal commit: %+v %v", r, err)
	}
	// Same original request must replay without another authority operation.
	_, err = s.ExecuteManaged(ctx, admin, API, Request{Operation: OpCommit, Key: "normal", ExpectedGeneration: staged.Generation}, g)
	if err != nil || g.arms != 1 {
		t.Fatal("replay crossed authority")
	}
}

func TestManagedPendingPersistenceAndHistoryRollback(t *testing.T) {
	c := firewallSample()
	s, engines, dir := fixture(t, Options{Initial: &c})
	ctx := context.Background()
	g := &testGuard{}
	initial := status(t, s)
	c.Rules[0].Action = "deny"
	staged := invoke(t, s, OpStage, &c, 0)
	pending, err := s.ExecuteManaged(ctx, admin, API, Request{Operation: OpCommit, Key: "lease", ExpectedGeneration: staged.Generation, ConfirmFor: 30 * time.Second}, g)
	if err != nil || pending.Pending.Lease != "lease" || g.confirms != 0 {
		t.Fatalf("pending %v", err)
	}
	history, _ := s.Revisions(admin, 0, 100)
	if len(history) != 1 || history[0].Revision.Hash != initial.Running.Hash {
		t.Fatal("provisional selectable")
	}
	g.inspect = func() {
		if s.state.Snapshot.Pending == nil {
			t.Fatal("pending removed before confirmation")
		}
	}
	confirmed, err := s.ExecuteManaged(ctx, admin, API, Request{Operation: OpConfirm, Key: "confirm", ExpectedGeneration: pending.Generation, Target: pending.Running.Hash}, g)
	if err != nil {
		t.Fatal(err)
	}
	g.inspect = nil
	history, _ = s.Revisions(admin, 0, 100)
	if len(history) != 2 {
		t.Fatal("missing history")
	}
	rolled, err := s.ExecuteManaged(ctx, admin, API, Request{Operation: OpRollback, Key: "rollback", ExpectedGeneration: confirmed.Generation, Target: initial.Running.Hash}, g)
	if err != nil || rolled.Running.Hash != initial.Running.Hash || rolled.Startup.Hash != initial.Startup.Hash {
		t.Fatalf("rollback %v", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := status(t, reopened); got.Running.Hash != initial.Running.Hash || got.Running.Config.SchemaVersion != 2 {
		t.Fatal("reopen changed v2")
	}
}

func TestManagedFailedConfirmCompensatesNormalAndRetainsPending(t *testing.T) {
	for _, ttl := range []time.Duration{0, 30 * time.Second} {
		t.Run(fmt.Sprint(ttl), func(t *testing.T) {
			s, engines, _ := fixture(t, Options{})
			initial := status(t, s)
			c := sample("new")
			staged := invoke(t, s, OpStage, &c, 0)
			g := &testGuard{fail: true}
			ctx := context.Background()
			r, err := s.ExecuteManaged(ctx, admin, API, Request{Operation: OpCommit, Key: "commit", ExpectedGeneration: staged.Generation, ConfirmFor: ttl}, g)
			if ttl == 0 {
				if !errors.Is(err, ErrEngine) || engines[0].Current() != initial.Running.Hash {
					t.Fatal("normal failure not compensated")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.ExecuteManaged(ctx, admin, API, Request{Operation: OpConfirm, Key: "confirm", ExpectedGeneration: r.Generation, Target: r.Running.Hash}, g)
			if !errors.Is(err, ErrRecovery) || s.state.Snapshot.Pending == nil {
				t.Fatal("failed confirm published")
			}
		})
	}
}

package configpoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func ruleStateConfig() Config {
	c := firewallSample()
	c.SchemaVersion = 4
	enabled := true
	c.Rules[0].Enabled = &enabled
	return c
}

func TestRuleStateConfirmedTimeoutAndApplyFailureRestoreEnabledRevision(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			initial := ruleStateConfig()
			s, engines, _ := fixture(t, Options{Initial: &initial})
			before := status(t, s)
			c := ruleStateConfig()
			*c.Rules[0].Enabled = false
			invoke(t, s, OpStage, &c, 0)
			invoke(t, s, OpValidate, nil, 0)
			if failure {
				engines[1].FailNext("after")
			}
			staged := status(t, s)
			pending, err := s.Execute(context.Background(), admin, API, Request{Operation: OpCommit, Key: "state-confirmed", ExpectedGeneration: staged.Generation, ConfirmFor: time.Minute})
			if failure {
				if err == nil {
					t.Fatal("partial apply accepted")
				}
			} else {
				if err != nil || pending.Pending == nil || pending.Running.Config.Rules[0].IsEnabled() {
					t.Fatal("disabled pending state missing", err)
				}
				if _, err = s.Execute(context.Background(), admin, API, Request{Operation: OpSave, Key: "save-pending", ExpectedGeneration: pending.Generation}); !errors.Is(err, ErrPending) {
					t.Fatal("pending change saved")
				}
				s.mu.Lock()
				s.deadline = time.Now().Add(-time.Second)
				s.armTimer()
				s.mu.Unlock()
			}
			after := status(t, s)
			if after.Running.Hash != before.Running.Hash || !after.Running.Config.Rules[0].IsEnabled() || after.Pending != nil {
				t.Fatal("enabled revision not restored")
			}
		})
	}
}

func TestRuleStateLegacyWireAndExplicitVersion(t *testing.T) {
	type legacyRule struct {
		ID     string `json:"id"`
		Action string `json:"action"`
		Match  *Match `json:"match,omitempty"`
	}
	for _, c := range []Config{sample("old"), firewallSample(), localSample(t, 18443)} {
		r, err := Canonical(c)
		if err != nil {
			t.Fatal(err)
		}
		oldRules := []legacyRule{}
		for _, rule := range r.Config.Rules {
			oldRules = append(oldRules, legacyRule{rule.ID, rule.Action, rule.Match})
		}
		old := struct {
			SchemaVersion int          `json:"schema_version"`
			DefaultAction string       `json:"default_action"`
			Rules         []legacyRule `json:"rules"`
			LocalServices any          `json:"local_services,omitempty"`
		}{SchemaVersion: r.Config.SchemaVersion, DefaultAction: r.Config.DefaultAction, Rules: oldRules}
		if r.Config.LocalServices != nil {
			old.LocalServices = r.Config.LocalServices
		}
		want, _ := json.Marshal(old)
		got, _ := json.Marshal(r.Config)
		sum := sha256.Sum256(want)
		if string(got) != string(want) || r.Hash != hex.EncodeToString(sum[:]) {
			t.Fatal("legacy serialization changed", c.SchemaVersion)
		}
		if len(c.Rules) > 0 {
			v := true
			c.Rules[0].Enabled = &v
			if _, err = Canonical(c); !errors.Is(err, ErrInvalid) {
				t.Fatal("legacy state extension accepted")
			}
		}
	}
	c := ruleStateConfig()
	r, err := Canonical(c)
	if err != nil {
		t.Fatal(err)
	}
	*c.Rules[0].Enabled = false
	if !r.Config.Rules[0].IsEnabled() {
		t.Fatal("state pointer aliases input")
	}
	disabled, err := Canonical(c)
	if err != nil || disabled.Hash == r.Hash {
		t.Fatal("disabled state absent from revision")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Rules[0].Enabled = nil }, func(c *Config) { c.Rules[0].Action = "invalid" }, func(c *Config) { c.Rules[0].Match.Protocol = "icmp" }, func(c *Config) { c.Rules = append(c.Rules, c.Rules[0]) }, func(c *Config) { c.LocalServices = localSample(t, 18443).LocalServices }} {
		bad := clone(c)
		mutate(&bad)
		if _, err := Canonical(bad); !errors.Is(err, ErrInvalid) {
			t.Fatal("inactive rule escaped validation")
		}
	}
	c.Rules = nil
	for i := 0; i < 65; i++ {
		rule := disabled.Config.Rules[0]
		rule.ID = fmt.Sprintf("off-%d", i)
		c.Rules = append(c.Rules, rule)
	}
	if _, err := Canonical(c); !errors.Is(err, ErrInvalid) {
		t.Fatal("inactive rules escaped resource bound")
	}
	c.Rules = c.Rules[:64]
	if _, err := Canonical(c); err != nil {
		t.Fatal(err)
	}
	a, _ := Canonical(c)
	c.Rules[0], c.Rules[1] = c.Rules[1], c.Rules[0]
	b, _ := Canonical(c)
	if a.Hash == b.Hash {
		t.Fatal("inactive priority lost")
	}
}

func TestRuleStatePersistenceReplayAndHistoricalRollback(t *testing.T) {
	legacy := firewallSample()
	s, engines, dir := fixture(t, Options{Initial: &legacy})
	previous := status(t, s)
	c := ruleStateConfig()
	*c.Rules[0].Enabled = false
	r := Request{Operation: OpStage, Key: "disable-stage", ExpectedGeneration: previous.Generation, Config: &c}
	staged, err := s.Execute(context.Background(), admin, Web, r)
	if err != nil {
		t.Fatal(err)
	}
	if staged.Running.Hash != previous.Running.Hash || staged.Candidate.Revision.Config.Rules[0].IsEnabled() {
		t.Fatal("stage changed effective state")
	}
	invoke(t, s, OpValidate, nil, 0)
	committed := invoke(t, s, OpCommit, nil, 0)
	invoke(t, s, OpSave, nil, 0)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	now := status(t, opened)
	if now.Running.Hash != committed.Running.Hash || now.Startup.Hash != committed.Running.Hash || now.Running.Config.Rules[0].IsEnabled() {
		t.Fatal("state not durable")
	}
	replay, err := opened.Execute(context.Background(), admin, CLI, r)
	if err != nil || replay.ReplayedGeneration != staged.Generation {
		t.Fatal("durable request fingerprint changed", err)
	}
	r.Config = clone(r.Config)
	*r.Config.Rules[0].Enabled = true
	if _, err = opened.Execute(context.Background(), admin, API, r); !errors.Is(err, ErrReplay) {
		t.Fatal("same key changed enabled state")
	}
	before := status(t, opened)
	rolled, err := opened.Execute(context.Background(), admin, API, Request{Operation: OpRollback, Key: "restore-legacy", ExpectedGeneration: before.Generation, Target: previous.Running.Hash})
	if err != nil || rolled.Running.Hash != previous.Running.Hash || rolled.Running.Config.SchemaVersion != 2 {
		t.Fatal("historical legacy restore failed", err)
	}
}

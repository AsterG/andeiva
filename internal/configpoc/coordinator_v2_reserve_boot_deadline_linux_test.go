//go:build linux

package configpoc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

type reserveSlowBootEngineV2 struct {
	base  *countedCoordinatorV2Engine
	mode  string
	armed *bool
	now   *time.Time
	fired bool
}

func (e *reserveSlowBootEngineV2) Name() string { return e.base.Name() }
func (e *reserveSlowBootEngineV2) delay(mode string) {
	if *e.armed && !e.fired && e.mode == mode {
		*e.now = e.now.Add(11 * time.Second)
		e.fired = true
	}
}
func (e *reserveSlowBootEngineV2) Validate(cfg Config) error {
	err := e.base.Validate(cfg)
	e.delay("validate")
	return err
}
func (e *reserveSlowBootEngineV2) Current() string {
	value := e.base.Current()
	e.delay("current")
	return value
}
func (e *reserveSlowBootEngineV2) Apply(ctx context.Context, r Revision) error {
	return e.base.Apply(ctx, r)
}

func TestReserveBootDeadlineCannotBeExtendedByCallbacks(t *testing.T) {
	for _, mode := range []string{"validate", "current", "between-components"} {
		t.Run(mode, func(t *testing.T) {
			c, area, engines, _ := bootFixtureV2(t)
			attachReserveManagerV2(t, c)
			now := c.now()
			c.options.Now = func() time.Time { return now }
			armed := false
			c.firewall[0] = &reserveSlowBootEngineV2{base: engines[0], mode: mode, armed: &armed, now: &now}
			hook := func(point string) error {
				if point == "after_boot_intent" {
					armed = true
				}
				if mode == "between-components" && point == "after_boot_engine" {
					now = now.Add(11 * time.Second)
				}
				return nil
			}
			reopened, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), hook)
			if !errors.Is(err, ErrRecovery) || reopened == nil || reopened.store.state.Configuration.Intent == nil || reopened.store.state.SystemBundle == nil || reopened.store.state.SystemBundle.CanonicalHeld || reopened.store.state.Configuration.LastCompletedBoot != "" {
				t.Fatal("late boot lost mutation fence", err)
			}
			allowed := int64(0)
			if mode == "between-components" {
				allowed = 1
			}
			if engines[0].applies.Load() != allowed || engines[1].applies.Load() != 0 {
				t.Fatal("expired boot reached extra components")
			}
		})
	}
}

type reserveRelativeBootGuardV2 struct {
	*countedCoordinatorV2Engine
	relative, confirms int
}

func (g *reserveRelativeBootGuardV2) Arm(context.Context, string, Revision, Revision, time.Duration) error {
	g.relative++
	return nil
}
func (g *reserveRelativeBootGuardV2) Confirm(context.Context, string, string) error {
	g.confirms++
	return nil
}

type reserveAbsoluteBootGuardV2 struct {
	*reserveRelativeBootGuardV2
	deadlines []time.Time
}

func (g *reserveAbsoluteBootGuardV2) ArmUntil(_ context.Context, _ string, _, _ Revision, deadline time.Time) error {
	g.deadlines = append(g.deadlines, deadline)
	return nil
}

func TestReserveBootRejectsRelativeOnlyGuardBeforeSystemClaim(t *testing.T) {
	c, area, engines, _ := bootFixtureV2(t)
	m := attachReserveManagerV2(t, c)
	guard := &reserveRelativeBootGuardV2{countedCoordinatorV2Engine: engines[0]}
	c.firewall[0] = guard
	reopened, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), nil)
	if !errors.Is(err, ErrRecovery) || reopened == nil || reopened.store.state.SystemBundle != nil || reopened.store.state.Configuration.Intent != nil || guard.relative != 0 || guard.confirms != 0 {
		t.Fatal("relative-only engine bypassed absolute boot gate", err)
	}
	claim, err := m.admission.ClaimClass("system-gate-probe", recoveryreserve.SystemV2)
	if err != nil || claim.Slot != 16 || claim.Epoch != 1 {
		t.Fatal("capability refusal consumed system resources", err)
	}
	for _, engine := range engines[:2] {
		if engine.applies.Load() != 0 {
			t.Fatal("unqualified real-guard contract applied")
		}
	}
}

func TestReserveBootAbsoluteGuardKeepsOriginalDeadline(t *testing.T) {
	c, area, engines, _ := bootFixtureV2(t)
	attachReserveManagerV2(t, c)
	guard := &reserveAbsoluteBootGuardV2{reserveRelativeBootGuardV2: &reserveRelativeBootGuardV2{countedCoordinatorV2Engine: engines[0]}}
	c.firewall[0] = guard
	booted, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), nil)
	if err != nil {
		t.Fatal(err)
	}
	var record v2RecoveryRecord
	if err = booted.store.readObject(booted.store.state.Configuration.LastCompletedBoot, &record); err != nil {
		t.Fatal(err)
	}
	if guard.relative != 0 || guard.confirms != 1 || len(guard.deadlines) != 2 {
		t.Fatal("absolute guard did not receive exact bounded lifecycle")
	}
	for _, deadline := range guard.deadlines {
		if !deadline.Equal(record.Started.Add(10 * time.Second)) {
			t.Fatal("boot refreshed original deadline")
		}
	}
}

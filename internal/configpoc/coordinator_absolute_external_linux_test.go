//go:build linux

package configpoc_test

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

type coordinatorAbsoluteAuthority struct {
	guardian *nftguardian.Guardian
	engine   configpoc.Engine
}

func (a coordinatorAbsoluteAuthority) ArmUntil(_ context.Context, id string, p, t configpoc.Revision, d time.Time) error {
	return a.guardian.ArmUntil(id, p, t, d)
}
func (a coordinatorAbsoluteAuthority) State(context.Context) (firewalladmin.LeaseState, error) {
	s := a.guardian.Status()
	return firewalladmin.LeaseState{Phase: s.Phase, ID: s.ID, Previous: s.Previous, Target: s.Target, Deadline: s.Deadline}, nil
}
func (a coordinatorAbsoluteAuthority) Current(context.Context) (string, error) {
	return a.engine.Current(), nil
}
func coordinatorAbsoluteScope(s firewalladmin.LeaseState) nftguardian.State {
	return nftguardian.State{ID: s.ID, Previous: s.Previous, Target: s.Target, Deadline: s.Deadline}
}
func (a coordinatorAbsoluteAuthority) ApplyLease(ctx context.Context, r configpoc.Revision, s firewalladmin.LeaseState) error {
	return a.guardian.ApplyLease(ctx, r, coordinatorAbsoluteScope(s))
}
func (a coordinatorAbsoluteAuthority) ConfirmLease(_ context.Context, s firewalladmin.LeaseState) error {
	return a.guardian.ConfirmLease(coordinatorAbsoluteScope(s))
}
func (a coordinatorAbsoluteAuthority) RecoverScoped(_ context.Context, s firewalladmin.LeaseState) error {
	return a.guardian.RecoverLease(s.ID, s.Previous, s.Target, s.Deadline)
}

func TestAbsoluteActualCoordinatorLifecycle(t *testing.T) {
	for _, scenario := range []string{"confirm", "expiry-restart", "immediate-gate"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				helpers := map[configpoc.Engine]*nftguardian.Guardian{}
				build := func(engine configpoc.Engine, previous configpoc.Revision) configpoc.Engine {
					guardian := helpers[engine]
					if guardian == nil {
						guardian = nftguardian.NewRestricted(engine)
						if err := guardian.Bootstrap(context.Background(), previous); err != nil {
							t.Fatal(err)
						}
						helpers[engine] = guardian
						t.Cleanup(func() { _ = guardian.Close() })
					}
					adapter, err := firewalladmin.NewPreparedAbsoluteGuardedEngine(engine, coordinatorAbsoluteAuthority{guardian, engine})
					if err != nil {
						t.Fatal(err)
					}
					return adapter
				}
				configpoc.ExerciseAbsoluteCoordinatorV2(t, build, scenario)
			})
		})
	}
}

package firewalladmin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

func TestPreparedStartupBootstrapAndLostReply(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "reply", true: "lost-reply"}[lost], func(t *testing.T) {
			_, _, previous, target := preparedGuardFixture(t)
			engine := configpoc.NewSimEngine("cold-startup")
			guardian := nftguardian.NewRestricted(engine)
			defer guardian.Close()
			authority := &preparedGuardAuthority{g: guardian, engine: engine}
			calls := 0
			adapter, err := NewPreparedStartupEngine(preparedGuardianEngine{engine, guardian}, authority, func(_ context.Context, s LeaseState) error {
				return guardian.RecoverLease(s.ID, s.Previous, s.Target, s.Deadline)
			}, func(ctx context.Context, r configpoc.Revision) error {
				calls++
				err := guardian.Bootstrap(ctx, r)
				if lost && err == nil {
					return errors.New("lost reply")
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if adapter.Apply(ctx, target) == nil {
				t.Fatal("unarmed Apply accepted")
			}
			if err := adapter.BootstrapStartup(ctx, "durable-boot", target); err != nil {
				t.Fatal(err)
			}
			if err := adapter.ConfirmStartup(ctx, "durable-boot", previous, target); err != nil {
				t.Fatal(err)
			}
			if adapter.BootstrapStartup(ctx, "durable-boot", target) == nil || calls != 1 {
				t.Fatal("bootstrap repeated")
			}
			if err := guardian.Arm("foreign", target, previous, time.Minute); err != nil {
				t.Fatal(err)
			}
			before := guardian.Status()
			if adapter.ConfirmStartup(ctx, "durable-boot", previous, target) == nil || guardian.Status() != before || engine.Current() != target.Hash {
				t.Fatal("foreign lease accepted or changed")
			}
		})
	}
}

func TestPreparedStartupConfirmsExistingExactLease(t *testing.T) {
	guard, authority, previous, target := preparedGuardFixture(t)
	adapter, err := NewPreparedStartupEngine(guard.engine, authority, guard.recoverLease, func(ctx context.Context, r configpoc.Revision) error { return authority.g.Bootstrap(ctx, r) })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := adapter.Arm(ctx, "boot-lease", previous, target, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Apply(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ConfirmStartup(ctx, "boot-lease", previous, target); err != nil {
		t.Fatal(err)
	}
	if authority.g.Status().Phase != "idle" || authority.engine.Current() != target.Hash {
		t.Fatal("exact boot lease not confirmed")
	}
}

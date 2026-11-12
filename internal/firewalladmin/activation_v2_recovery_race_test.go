package firewalladmin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestPreparedGuardRecoveryMustNotConsumeReplacementLease(t *testing.T) {
	for _, sameID := range []bool{false, true} {
		name := "foreign-id"
		if sameID {
			name = "same-id-new-deadline"
		}
		t.Run(name, func(t *testing.T) {
			guard, authority, previous, target := preparedGuardFixture(t)
			ctx := context.Background()
			if guard.Arm(ctx, "original", previous, target, time.Minute) != nil || guard.Apply(ctx, target) != nil {
				t.Fatal("fixture arm/apply")
			}
			var replacement LeaseState
			replacementTarget := target
			if !sameID {
				config := target.Config
				config.Rules = append([]configpoc.Rule(nil), config.Rules...)
				config.Rules[0].ID = "foreign-rule"
				var err error
				replacementTarget, err = configpoc.Canonical(config)
				if err != nil {
					t.Fatal(err)
				}
			}
			guard.recoverLease = func(_ context.Context, observed LeaseState) error {
				// A second trusted writer replaces the lease after observation.
				if err := authority.g.RecoverPrevious(); err != nil {
					return err
				}
				id := "replacement"
				if sameID {
					id = "original"
				}
				if err := authority.g.Arm(id, previous, replacementTarget, 2*time.Minute); err != nil {
					return err
				}
				if err := authority.g.Apply(ctx, replacementTarget); err != nil {
					return err
				}
				var err error
				replacement, err = authority.State(ctx)
				if err != nil {
					return err
				}
				return authority.g.RecoverLease(observed.ID, observed.Previous, observed.Target, observed.Deadline)
			}
			if err := guard.RecoverPrevious(ctx, "original", previous, target); !errors.Is(err, configpoc.ErrRecovery) {
				t.Fatal("replacement accepted", err)
			}
			state, err := authority.State(ctx)
			if err != nil || state != replacement || state.Phase != "pending" || authority.engine.Current() != replacementTarget.Hash {
				t.Fatal("replacement lease changed", state, replacement, err)
			}
		})
	}
}

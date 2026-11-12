package firewalladmin

import (
	"context"
	"testing"
	"time"
)

func TestPreparedGuardRecoveryMustNotConsumeReplacementLease(t *testing.T) {
	guard, authority, previous, target := preparedGuardFixture(t)
	ctx := context.Background()
	if guard.Arm(ctx, "original", previous, target, time.Minute) != nil || guard.Apply(ctx, target) != nil { t.Fatal("fixture arm/apply") }
	guard.recovered = func(context.Context) error {
		// Another trusted writer recovers the original and installs its own
		// valid lease after the wrapper's observation, before recovery executes.
		if err := authority.g.RecoverPrevious(); err != nil { return err }
		if err := authority.g.Arm("replacement", previous, target, time.Minute); err != nil { return err }
		if err := authority.g.Apply(ctx, target); err != nil { return err }
		return authority.g.RecoverPrevious()
	}
	err := guard.RecoverPrevious(ctx, "original", previous, target)
	state := authority.g.Status()
	if err == nil || state.ID != "replacement" || state.Phase != "pending" || authority.engine.Current()!=target.Hash {
		t.Fatalf("replacement lease consumed: result=%v phase=%s id=%q current=%s",err,state.Phase,state.ID,authority.engine.Current())
	}
}

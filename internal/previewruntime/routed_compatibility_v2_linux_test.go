//go:build linux

package previewruntime

import (
	"context"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/firewalladmin"
)

func TestRoutedCompatibilityV2DeniesEveryEffectAfterAttachment(t *testing.T) {
	for _, verb := range []string{"bootstrap", "apply", "arm", "arm_until", "apply_scoped", "confirm", "confirm_scoped", "recover_scoped"} {
		t.Run(verb, func(t *testing.T) {
			s, guardian, engine, before, target := fixtureSessionV2(t)
			ctx := context.Background()
			if verb != "bootstrap" {
				initial := initializeV2(t, s, before)
				initial.stop()
			}
			if verb == "apply" || verb == "apply_scoped" || verb == "confirm" || verb == "confirm_scoped" || verb == "recover_scoped" {
				if err := guardian.Arm("forbidden", before, target, 5*time.Second); err != nil {
					t.Fatal(err)
				}
				if verb == "confirm" || verb == "confirm_scoped" || verb == "recover_scoped" {
					if err := guardian.Apply(ctx, target); err != nil {
						t.Fatal(err)
					}
				}
			}
			wantState, wantHash := guardian.Status(), engine.Current()
			readOnly, err := NewRoutedCompatibilitySessionV2(s.base.run, s.base.namespace, s.base.engine, guardian, s.base.observe)
			if err != nil {
				t.Fatal(err)
			}
			conn := dialSessionV2(t, readOnly, nil)
			attachV2(t, conn.client)
			observation, err := conn.client.Snapshot(ctx)
			if err != nil || observation.Hash != wantHash {
				t.Fatal("read-only observation failed", err)
			}
			lease := stateV2(wantState)
			if verb == "arm" || verb == "arm_until" {
				lease = firewalladmin.LeaseState{ID: "forbidden", Previous: before.Hash, Target: target.Hash, Deadline: time.Now().UTC().Add(5 * time.Second)}
			}
			var denied error
			switch verb {
			case "bootstrap":
				denied = conn.client.Bootstrap(ctx, target)
			case "apply":
				denied = conn.client.Apply(ctx, target)
			case "arm":
				denied = conn.client.Arm(ctx, lease.ID, before, target, time.Second)
			case "arm_until":
				denied = conn.client.ArmUntil(ctx, lease.ID, before, target, lease.Deadline)
			case "apply_scoped":
				denied = conn.client.ApplyLease(ctx, target, lease)
			case "confirm":
				denied = conn.client.Confirm(ctx, lease.ID, target.Hash)
			case "confirm_scoped":
				denied = conn.client.ConfirmLease(ctx, lease)
			case "recover_scoped":
				denied = conn.client.RecoverScoped(ctx, lease)
			}
			conn.stop()
			if denied == nil || engine.Current() != wantHash || guardian.Status() != wantState {
				t.Fatal("compatibility channel changed policy or guardian", denied)
			}
			// A fresh controller cannot upgrade this helper incarnation to writes.
			reconnected := dialSessionV2(t, readOnly, nil)
			attachV2(t, reconnected.client)
			if reconnected.client.Apply(ctx, target) == nil || engine.Current() != wantHash || guardian.Status() != wantState {
				t.Fatal("reconnect escalated read-only authority")
			}
			reconnected.stop()
		})
	}
}

func TestRoutedCompatibilityV2RequiresCompleteAuthority(t *testing.T) {
	if _, err := NewRoutedCompatibilitySessionV2("", 0, nil, nil, nil); err == nil {
		t.Fatal("invalid compatibility assembly accepted")
	}
}

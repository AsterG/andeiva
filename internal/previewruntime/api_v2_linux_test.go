//go:build linux

package previewruntime

import (
	"context"
	"testing"
	"time"
)

func TestRuntimeV2APIClosePreservesHelperPolicy(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending-expires-independently", true: "confirmed-remains"}[confirmed], func(t *testing.T) {
			s, g, engine, previous, target := fixtureSessionV2(t)
			conn := initializeV2(t, s, previous)
			ctx := context.Background()
			deadline := time.Now().UTC().Add(800 * time.Millisecond)
			if err := conn.client.ArmUntil(ctx, "api-close", previous, target, deadline); err != nil {
				t.Fatal(err)
			}
			receipt, err := conn.client.State(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = conn.client.ApplyLease(ctx, target, receipt); err != nil {
				t.Fatal(err)
			}
			if confirmed {
				if err = conn.client.ConfirmLease(ctx, receipt); err != nil {
					t.Fatal(err)
				}
			}
			runtime := &OperationsRuntimeV2{client: conn.client}
			if err = runtime.Close(); err != nil {
				t.Fatal(err)
			}
			conn.stop()
			if engine.Current() != target.Hash {
				t.Fatal("API close deleted/restored effective policy")
			}
			if confirmed {
				if g.Status().Phase != "idle" || g.Status().ID != "api-close" {
					t.Fatal("API close cleared confirmed receipt")
				}
			} else {
				limit := time.Now().Add(2 * time.Second)
				for engine.Current() != previous.Hash && time.Now().Before(limit) {
					time.Sleep(10 * time.Millisecond)
				}
				if engine.Current() != previous.Hash || g.Status().Phase != "expired" {
					t.Fatal("helper deadline did not recover independently")
				}
			}
		})
	}
}

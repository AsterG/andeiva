//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Physical networking is explicitly doubled by the fixture. Selected files,
// full history, R2 pools and final-reader revalidation are real.
func TestRoutedRetirementSourceV3CurrentActiveAndDHCPPriority(t *testing.T) {
	r, c, _, writer, _ := selectedDHCPReaderFixtureV3(t)
	ctx := context.Background()
	old := r.options.Identity
	calls := 0
	observe := func(s RoutedRetirementSourceV3) error {
		calls++
		if !s.Valid() || s.Identity() != old {
			t.Fatal("invalid callback source")
		}
		return nil
	}
	active, err := r.ObserveRetirementSourceV3(ctx, old, observe)
	if err != nil || !active.Valid() || active.Reference().WorkHash != c.store.state.RoutedActive.Work || calls != 1 {
		t.Fatal("current active source", err)
	}
	work, err := writer.Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := r.ObserveRetirementSourceV3(ctx, old, observe)
	if err != nil || lease.Reference().WorkHash != work || lease.Reference().WorkHash == active.Reference().WorkHash || calls != 2 {
		t.Fatal("DHCP current work did not dominate historical active", err)
	}
}
func TestRoutedRetirementSourceV3RejectsWrongIdentityPolicyAndCorruption(t *testing.T) {
	r, c, _, _, _ := selectedDHCPReaderFixtureV3(t)
	ctx := context.Background()
	old := r.options.Identity
	calls := 0
	observe := func(RoutedRetirementSourceV3) error { calls++; return nil }
	wrong := old
	wrong.RunID = strings.Repeat("f", 32)
	if s, err := r.ObserveRetirementSourceV3(ctx, wrong, observe); err == nil || s.Valid() || calls != 0 {
		t.Fatal("caller old accepted")
	}
	r.options.Policy = SelectionActionAuthorityV2
	if s, err := r.ObserveRetirementSourceV3(ctx, old, observe); err == nil || s.Valid() || calls != 0 {
		t.Fatal("action-only proof accepted")
	}
	r.options.Policy = SelectionFullHistoryV2
	name, err := v2ObjectName(c.store.state.Configuration.AuditTip)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(c.store.root.Name(), name), []byte("{}"), 0640); err != nil {
		t.Fatal(err)
	}
	if s, err := r.ObserveRetirementSourceV3(ctx, old, observe); err == nil || s.Valid() || calls != 0 {
		t.Fatal("corrupt G1 reached callback", err)
	}
}
func TestRoutedRetirementSourceV3FinalRevalidationRejectsPublication(t *testing.T) {
	r, c, _, _, _ := selectedDHCPReaderFixtureV3(t)
	calls := 0
	source, err := r.ObserveRetirementSourceV3(context.Background(), r.options.Identity, func(RoutedRetirementSourceV3) error { calls++; return c.store.publish(clone(c.store.state)) })
	if err == nil || source.Valid() || calls != 1 {
		t.Fatal("changed selected publication escaped", err, calls)
	}
}
func TestRoutedRetirementSourceV3UnselectedAndOrdinaryIntentRefused(t *testing.T) {
	r, _, _ := selectedIntentFixtureV2(t)
	calls := 0
	source, err := r.ObserveRetirementSourceV3(context.Background(), r.options.Identity, func(RoutedRetirementSourceV3) error { calls++; return nil })
	if err == nil || source.Valid() || calls != 0 {
		t.Fatal("unsupported intent authorized retirement", err)
	}
	if (RoutedRetirementSourceV3{}).Valid() {
		t.Fatal("zero source valid")
	}
}

func TestRoutedRetirementSourceV3BootAndPendingCurrentScope(t *testing.T) {
	for _, mode := range []string{"boot", "pending"} {
		t.Run(mode, func(t *testing.T) {
			c, a, principal, cfg := boundaryCoordinatorFixtureV2(t)
			r := sharedBoundaryReaderV2(t, c, a)
			ctx := context.Background()
			expected := ""
			if mode == "boot" {
				boot := v2BootID(a.identity.BootID)
				c.options.BootID = &boot
				c.options.Hook = func(point string) error {
					if point == "after_boot_intent" {
						return ErrInterrupted
					}
					return nil
				}
				if err := c.bootStartupLocked(ctx, boot); !errors.Is(err, ErrInterrupted) {
					t.Fatal(err)
				}
				expected = c.store.state.Configuration.Intent.RoutedWork
			} else {
				if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &cfg}); err != nil {
					t.Fatal(err)
				}
				seconds := uint64(60)
				op, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
				if err != nil {
					t.Fatal(err)
				}
				retained, err := c.store.lookupRetained(principal.Subject, op.ID)
				if err != nil || retained.Reserve == nil || retained.Reserve.PlanIntent == nil {
					t.Fatal("pending reserve", err)
				}
				expected = retained.Reserve.PlanIntent.RoutedWork
			}
			source, err := r.ObserveRetirementSourceV3(ctx, a.identity, func(RoutedRetirementSourceV3) error { return nil })
			if err != nil || !source.Valid() || source.Reference().WorkHash != expected {
				t.Fatal("current scope", mode, err)
			}
		})
	}
}

package previewruntime

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// Orchestration with explicit selected-store and kernel doubles. Real gate
// readback, irreversible fence and sequence checks have networkexecutor tests.
func TestRoutedDHCPTerminalRetirementRequiresExactArchive(t *testing.T) {
	for _, mode := range []string{"complete", "missing-archive", "other-archive", "active-work", "target", "release-failure", "dispose-failure"} {
		t.Run(mode, func(t *testing.T) {
			r, k, reader, _ := dhcpRuntimeFixtureV3(t)
			ctx := context.Background()
			g, err := r.begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			work := &dhcpRuntimeWorkV3{grant: g, phase: "prepared", hash: strings.Repeat("c", 64)}
			reader.work = work
			if r.apply(ctx, work.hash) != nil {
				t.Fatal("apply")
			}
			work.phase = "applied"
			if r.open(ctx, work.hash) != nil || r.withdraw(ctx, work.hash) != nil {
				t.Fatal("open/withdraw")
			}
			reader.work, reader.last = nil, &g.Snapshot
			switch mode {
			case "missing-archive":
				reader.last = nil
			case "other-archive":
				other := g.Snapshot
				other.Sequence++
				reader.last = &other
			case "active-work":
				reader.work = work
			case "target":
				k.target = true
			case "dispose-failure":
				k.failDispose = true
			}
			releases, builds := 0, 0
			r.releaseLease = func(context.Context) error {
				releases++
				if mode == "release-failure" {
					return errors.New("release failed")
				}
				return nil
			}
			r.buildGate = func(context.Context, networkexecutor.LeaseGateAuthority) (routedDHCPGateV3, error) {
				builds++
				return nil, configpoc.ErrRecovery
			}
			lease, gate := r.lease, r.gate
			err = r.retire(ctx)
			if mode == "complete" {
				if err != nil || releases != 1 || !k.disposed || r.lease != nil || r.gate != nil || r.work != "" || r.withdrawn || r.failed {
					t.Fatal("terminal resources not released", err)
				}
				// Reconstruction is only possible after complete retirement, and
				// the normal begin path must authenticate the archived witness.
				_, _ = r.begin(ctx)
				if builds != 1 {
					t.Fatal("normal gate reconstruction path not reached")
				}
				return
			}
			if err == nil || r.lease != lease || r.gate != gate || r.work != work.hash || !reflect.DeepEqual(r.grant, g) || !r.withdrawn {
				t.Fatal("failed retirement discarded recovery references", err)
			}
			if mode == "release-failure" || mode == "dispose-failure" {
				if !r.failed || releases != 1 {
					t.Fatal("resource failure did not fence runtime")
				}
				if r.retire(ctx) == nil {
					t.Fatal("failed release retried")
				}
				_, _ = r.begin(ctx)
				if builds != 0 || releases != 1 {
					t.Fatal("uncertain disposal permitted reconstruction/release retry")
				}
			} else if releases != 0 || k.disposed {
				t.Fatal("unproven archive or baseline released resources")
			}
		})
	}
}

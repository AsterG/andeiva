package previewruntime

import (
	"context"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

// Models a source whose continuation authority is fixed by capture, while the
// independently observed selected tuple can advance to a later Confirm Intent.
type integrityAnchorSourceV3 struct {
	routedTransportReaderV3
	captured configpoc.SelectionReferenceV2
	captures int
}

func (s *integrityAnchorSourceV3) CaptureColdAnchorV1(_ context.Context, ref configpoc.SelectionReferenceV2) error {
	s.captured = ref
	s.captures++
	return nil
}
func (s *integrityAnchorSourceV3) ResolveFencedContinuationV1(_ context.Context, _ firewallipc.RoutedReferenceV3, purpose string) (configpoc.RoutedSelectedPlanV1, error) {
	if purpose != "recover" || s.captured.Sequence != 3 {
		return configpoc.RoutedSelectedPlanV1{}, configpoc.ErrRecovery
	}
	return configpoc.RoutedSelectedPlanV1{}, nil
}

func TestRoutedIntegrityV3ReattachCannotReplaceFencedAnchor(t *testing.T) {
	for _, phase := range []routedIntegrityPhaseV3{routedIntegrityReconcilingV3, routedIntegrityFencedV3} {
		t.Run(string(phase), func(t *testing.T) {
			session, reader, marker := integritySessionFixtureV3(t)
			source := &integrityAnchorSourceV3{}
			g := session.integrity
			g.source = source
			original := reader.ref
			if result, err := g.attach(context.Background(), original); err != nil || result.State != configpoc.IntegrityCompleteV1 {
				t.Fatal(result, err)
			}
			g.phase = phase
			if phase == routedIntegrityFencedV3 {
				_ = marker.MarkBlocked()
			}
			// A later selection is correlation, never replacement recovery authority.
			reader.ref.Sequence++
			reader.ref.Generation++
			if result, err := g.attach(context.Background(), reader.ref); err != nil || result.State != configpoc.IntegrityCompleteV1 {
				t.Fatal(result, err)
			}
			if g.anchor != original || source.captured != original || source.captures != 1 {
				t.Fatal("reattach replaced prior opaque authority")
			}
			if phase == routedIntegrityFencedV3 {
				if _, err := g.resolve(context.Background(), source, firewallipc.RoutedReferenceV3{}, "confirm"); err == nil {
					t.Fatal("new Confirm authorized")
				}
				if _, err := g.resolve(context.Background(), source, firewallipc.RoutedReferenceV3{}, "recover"); err != nil {
					t.Fatal("original recovery lost", err)
				}
			}
		})
	}
	// A process reopening an already blocked marker has no historical RAM token.
	session, reader, marker := integritySessionFixtureV3(t)
	source := &integrityAnchorSourceV3{}
	session.integrity.source = source
	_ = marker.MarkBlocked()
	result, err := session.integrity.attach(context.Background(), reader.ref)
	if err != nil || result.State != configpoc.IntegrityFencedV1 || source.captures != 0 || session.integrity.anchor != (configpoc.SelectionReferenceV2{}) {
		t.Fatal("fresh fenced helper captured new authority", result, err)
	}
}

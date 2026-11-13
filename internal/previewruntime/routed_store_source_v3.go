package previewruntime

import (
	"context"
	"strconv"
	"sync"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

// RoutedStoreSourceV3 resolves expectations through a helper-owned reader. It
// never opens the API's writer or accepts a decoded plan as authority.
type RoutedStoreSourceV3 struct {
	reader *configpoc.RoutedSelectionReaderV2
	coldMu sync.Mutex
	cold   configpoc.RoutedColdAnchorV1
}

func NewRoutedStoreSourceV3(reader *configpoc.RoutedSelectionReaderV2) (*RoutedStoreSourceV3, error) {
	if reader == nil {
		return nil, ErrIdentity
	}
	return &RoutedStoreSourceV3{reader: reader}, nil
}
func (s *RoutedStoreSourceV3) Resolve(ctx context.Context, expected firewallipc.RoutedReferenceV3, action string) (configpoc.RoutedSelectedPlanV1, error) {
	if s == nil || s.reader == nil || !expected.Valid() {
		return configpoc.RoutedSelectedPlanV1{}, configpoc.ErrRecovery
	}
	purpose, err := routedPurposeV3(action)
	if err != nil {
		return configpoc.RoutedSelectedPlanV1{}, err
	}
	generation, e := strconv.ParseUint(expected.Generation, 10, 64)
	if e != nil {
		return configpoc.RoutedSelectedPlanV1{}, configpoc.ErrInvalid
	}
	plan, e := s.reader.ResolveCurrent(ctx, configpoc.RoutedWorkReferenceV1{Work: expected.Work, Lineage: expected.Lineage, Generation: generation}, purpose)
	if e != nil {
		return configpoc.RoutedSelectedPlanV1{}, e
	}
	return plan, nil
}
func (s *RoutedStoreSourceV3) PrepareView(ctx context.Context) (RoutedPreparationViewV3, error) {
	if s == nil || s.reader == nil {
		return RoutedPreparationViewV3{}, configpoc.ErrRecovery
	}
	view, e := s.reader.PrepareCurrentView(ctx)
	if e != nil {
		return RoutedPreparationViewV3{}, e
	}
	return RoutedPreparationViewV3{Baseline: view.Baseline, Startup: view.Startup, Saved: view.Saved}, nil
}

var _ RoutedSelectionSourceV3 = (*RoutedStoreSourceV3)(nil)

// Capture is invoked only for a new authenticated controller attachment. The
// opaque token is retained in helper memory and never reconstructed from JSON.
func (s *RoutedStoreSourceV3) CaptureColdAnchorV1(ctx context.Context, expected configpoc.SelectionReferenceV2) error {
	if s == nil || s.reader == nil {
		return configpoc.ErrRecovery
	}
	token, err := s.reader.CaptureColdAnchorV1(ctx)
	if err != nil {
		return err
	}
	if token.Reference() != expected {
		return configpoc.ErrConflict
	}
	s.coldMu.Lock()
	defer s.coldMu.Unlock()
	s.cold = token
	return nil
}
func (s *RoutedStoreSourceV3) ResolveColdContinuationV1(ctx context.Context, expected firewallipc.RoutedReferenceV3, action string) (configpoc.RoutedSelectedPlanV1, error) {
	if s == nil || s.reader == nil || !expected.Valid() {
		return configpoc.RoutedSelectedPlanV1{}, configpoc.ErrRecovery
	}
	purpose, err := routedPurposeV3(action)
	if err != nil {
		return configpoc.RoutedSelectedPlanV1{}, err
	}
	generation, err := strconv.ParseUint(expected.Generation, 10, 64)
	if err != nil {
		return configpoc.RoutedSelectedPlanV1{}, configpoc.ErrInvalid
	}
	s.coldMu.Lock()
	token := s.cold
	s.coldMu.Unlock()
	return s.reader.ResolveColdContinuationV1(ctx, token, configpoc.RoutedWorkReferenceV1{Work: expected.Work, Lineage: expected.Lineage, Generation: generation}, purpose)
}

func (s *RoutedStoreSourceV3) ResolveFencedContinuationV1(ctx context.Context, expected firewallipc.RoutedReferenceV3, action string) (configpoc.RoutedSelectedPlanV1, error) {
	if s == nil || s.reader == nil || !expected.Valid() {
		return configpoc.RoutedSelectedPlanV1{}, configpoc.ErrRecovery
	}
	purpose, err := routedPurposeV3(action)
	if err != nil {
		return configpoc.RoutedSelectedPlanV1{}, err
	}
	generation, err := strconv.ParseUint(expected.Generation, 10, 64)
	if err != nil {
		return configpoc.RoutedSelectedPlanV1{}, configpoc.ErrInvalid
	}
	s.coldMu.Lock()
	token := s.cold
	s.coldMu.Unlock()
	return s.reader.ResolveFencedContinuationV1(ctx, token, configpoc.RoutedWorkReferenceV1{Work: expected.Work, Lineage: expected.Lineage, Generation: generation}, purpose)
}

func routedPurposeV3(action string) (configpoc.RoutedSelectionPurposeV2, error) {
	switch action {
	case "arm":
		return configpoc.SelectionArmV2, nil
	case "apply":
		return configpoc.SelectionApplyV2, nil
	case "confirm":
		return configpoc.SelectionConfirmV2, nil
	case "recover":
		return configpoc.SelectionRecoverV2, nil
	case "bootstrap":
		return configpoc.SelectionBootstrapV2, nil
	case "resume":
		return configpoc.SelectionResumeV2, nil
	case "match_before":
		return configpoc.SelectionMatchBeforeV2, nil
	case "match_target":
		return configpoc.SelectionMatchTargetV2, nil
	default:
		return "", configpoc.ErrDenied
	}
}

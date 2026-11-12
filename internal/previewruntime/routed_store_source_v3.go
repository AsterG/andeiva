package previewruntime

import (
	"context"
	"strconv"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

// RoutedStoreSourceV3 resolves expectations through a helper-owned reader. It
// never opens the API's writer or accepts a decoded plan as authority.
type RoutedStoreSourceV3 struct {
	reader *configpoc.RoutedSelectionReaderV2
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
	var purpose configpoc.RoutedSelectionPurposeV2
	switch action {
	case "arm":
		purpose = configpoc.SelectionArmV2
	case "apply":
		purpose = configpoc.SelectionApplyV2
	case "confirm":
		purpose = configpoc.SelectionConfirmV2
	case "recover":
		purpose = configpoc.SelectionRecoverV2
	case "bootstrap":
		purpose = configpoc.SelectionBootstrapV2
	case "resume":
		purpose = configpoc.SelectionResumeV2
	case "match_before":
		purpose = configpoc.SelectionMatchBeforeV2
	case "match_target":
		purpose = configpoc.SelectionMatchTargetV2
	default:
		return configpoc.RoutedSelectedPlanV1{}, configpoc.ErrDenied
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

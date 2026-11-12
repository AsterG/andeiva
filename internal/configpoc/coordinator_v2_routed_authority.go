package configpoc

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

type RoutedPreparationV1 struct {
	Before       OwnedV1        `json:"before"`
	Target       OwnedV1        `json:"target"`
	Dependencies DependenciesV1 `json:"dependencies"`
}

type RoutedReceiptV1 struct {
	Phase, ID, Previous, Target string
	Deadline                    time.Time
}

// RoutedAuthorityV1 is a trusted, exclusive group capability. It must observe
// actual owned state and retain its independent lease after controller failure.
// No administrative request supplies this interface or its preparation data.
type RoutedAuthorityV1 interface {
	Identity() networkexecutor.OwnedNamespaceIdentity
	Prepare(context.Context, RoutedActivationBundleV1, *RoutedBaselineV1) (RoutedPreparationV1, error)
	PrepareBoot(context.Context, RoutedActivationBundleV1, RoutedActivationBundleV1) (RoutedPreparationV1, error)
	Observe(context.Context) (RoutedReceiptV1, string, error)
	Match(context.Context, RoutedSelectedPlanV1, string) error
	Resume(context.Context, RoutedSelectedPlanV1) error
	Arm(context.Context, RoutedSelectedPlanV1) error
	Apply(context.Context, RoutedSelectedPlanV1) error
	Confirm(context.Context, RoutedSelectedPlanV1) error
	Recover(context.Context, RoutedSelectedPlanV1) error
	Bootstrap(context.Context, RoutedSelectedPlanV1, time.Time) error
}

// Private fields prevent transport code from manufacturing a selected plan.
// Every accessor detaches data; a plan is issued only after selected-object and
// reservation verification under the coordinator writer lock.
type RoutedSelectedPlanV1 struct {
	work        v2RoutedWork
	preparation RoutedPreparationV1
	previous    RoutedActivationBundleV1
	target      RoutedActivationBundleV1
	baseline    *RoutedBaselineV1
	resolution  string
	bootRecord  *v2RecoveryRecord
}

func (p RoutedSelectedPlanV1) Transition() RoutedTransitionV1 { return p.work.Transition }
func (p RoutedSelectedPlanV1) Lease() string                  { return p.work.Lease }
func (p RoutedSelectedPlanV1) Deadline() time.Time            { return p.work.Deadline }
func (p RoutedSelectedPlanV1) Cold() bool                     { return p.work.Cold }
func (p RoutedSelectedPlanV1) Bundles() (*RoutedActivationBundleV1, RoutedActivationBundleV1) {
	if p.work.Cold {
		return nil, clone(p.target)
	}
	previous := clone(p.previous)
	return &previous, clone(p.target)
}
func (p RoutedSelectedPlanV1) Artifacts() RoutedPreparationV1 { return clone(p.preparation) }
func (p RoutedSelectedPlanV1) Baseline() *RoutedBaselineV1    { return clone(p.baseline) }
func (p RoutedSelectedPlanV1) Valid() bool {
	return p.work.Version == 1 && p.work.Transition.ValidShape() && p.work.Lease != "" && !p.work.Deadline.IsZero() && p.target.Composite.Hash != ""
}

type v2RoutedWork struct {
	Boundary     *v2RoutedBootBoundary `json:"boot_boundary,omitempty"`
	Scope        RoutedWorkScopeV1     `json:"scope"`
	Baseline     string                `json:"baseline,omitempty"`
	Kind         string                `json:"kind,omitempty"`
	BootRecord   string                `json:"boot_record,omitempty"`
	BootBaseline *RoutedBaselineV1     `json:"boot_baseline,omitempty"`
	Version      int                   `json:"version"`
	Lineage      string                `json:"lineage"`
	Operation    string                `json:"operation_id"`
	Subject      string                `json:"subject"`
	Generation   uint64                `json:"generation,string"`
	Lease        string                `json:"lease"`
	Deadline     time.Time             `json:"deadline"`
	Cold         bool                  `json:"cold"`
	Transition   RoutedTransitionV1    `json:"transition"`
}

type RoutedWorkScopeV1 struct {
	Version    int                                    `json:"version"`
	Identity   networkexecutor.OwnedNamespaceIdentity `json:"identity"`
	Lineage    string                                 `json:"lineage"`
	Generation uint64                                 `json:"generation,string"`
}

func validRoutedIdentityV1(identity networkexecutor.OwnedNamespaceIdentity) bool {
	if identity.UID == 0 || identity.GID == 0 || identity.Namespace == 0 || identity.Host == 0 || identity.Namespace == identity.Host || !validBootIDV2(v2BootID(identity.BootID)) || len(identity.RunID) != 32 || identity.RunID != strings.ToLower(identity.RunID) {
		return false
	}
	_, err := hex.DecodeString(identity.RunID)
	return err == nil
}

func (p RoutedSelectedPlanV1) Scope() RoutedWorkScopeV1 { return p.work.Scope }
func (p RoutedSelectedPlanV1) Resolution() string       { return p.resolution }

func routedWorkUsesNoNetworkV2(p RoutedSelectedPlanV1) bool {
	return p.work.Kind == OpCommit || p.work.Kind == OpRollback || p.preparation.Before.Version == 2 || p.preparation.Target.Version == 2 || p.preparation.Dependencies.Version == 2
}

type v2RoutedOwned struct {
	Version   int     `json:"version"`
	Lineage   string  `json:"lineage"`
	Operation string  `json:"operation_id"`
	Role      string  `json:"role"`
	Value     OwnedV1 `json:"value"`
}
type v2RoutedDependencies struct {
	Version   int            `json:"version"`
	Lineage   string         `json:"lineage"`
	Operation string         `json:"operation_id"`
	Value     DependenciesV1 `json:"value"`
}

type v2RoutedActive struct {
	Work string `json:"work"`
	Side string `json:"side"`
}

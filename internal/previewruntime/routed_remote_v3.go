package previewruntime

import (
	"context"
	"strconv"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// RoutedRemoteAuthority keeps management unprivileged. Only typed requests and
// selected-work references cross the private channel; a helper reconstructs all
// activation authority from its own pinned durable readers.
type RoutedRemoteAuthority struct {
	client   *firewallipc.RoutedClientV3
	identity networkexecutor.OwnedNamespaceIdentity
}

func NewRoutedRemoteAuthority(client *firewallipc.RoutedClientV3, identity networkexecutor.OwnedNamespaceIdentity) (*RoutedRemoteAuthority, error) {
	run, namespace := client.Scope()
	if client == nil || identity.UID == 0 || identity.GID == 0 || identity.Namespace == 0 || identity.Host == 0 || identity.Namespace == identity.Host || identity.Namespace != namespace || identity.RunID != run || !bootPattern.MatchString(identity.BootID) {
		return nil, ErrIdentity
	}
	return &RoutedRemoteAuthority{client: client, identity: identity}, nil
}
func (a *RoutedRemoteAuthority) Identity() networkexecutor.OwnedNamespaceIdentity { return a.identity }
func (a *RoutedRemoteAuthority) Close() error {
	if a == nil {
		return nil
	}
	return a.client.Close()
}
func (a *RoutedRemoteAuthority) Prepare(ctx context.Context, target configpoc.RoutedActivationBundleV1, baseline *configpoc.RoutedBaselineV1) (configpoc.RoutedPreparationV1, error) {
	expected := ""
	if baseline != nil {
		expected = baseline.Saved.Composite.Hash
	}
	value, e := a.client.Call(ctx, "prepare", firewallipc.RoutedPrepareV3{Target: target, Baseline: expected})
	return value.Preparation, e
}
func (a *RoutedRemoteAuthority) PrepareBoot(ctx context.Context, target, saved configpoc.RoutedActivationBundleV1) (configpoc.RoutedPreparationV1, error) {
	value, e := a.client.Call(ctx, "prepare_boot", firewallipc.RoutedPrepareV3{Target: target, Baseline: saved.Composite.Hash})
	return value.Preparation, e
}
func (a *RoutedRemoteAuthority) Observe(ctx context.Context) (configpoc.RoutedReceiptV1, string, error) {
	value, e := a.client.Call(ctx, "observe", struct{}{})
	r := value.Observed.Receipt
	return configpoc.RoutedReceiptV1{Phase: r.Phase, ID: r.ID, Previous: r.Previous, Target: r.Target, Deadline: r.Deadline}, value.Observed.Revision, e
}
func (a *RoutedRemoteAuthority) selected(ctx context.Context, verb string, p configpoc.RoutedSelectedPlanV1, side string) error {
	if a == nil || !p.Valid() || p.Scope().Identity != a.identity {
		return configpoc.ErrRecovery
	}
	ref := p.Reference()
	_, e := a.client.Call(ctx, verb, firewallipc.RoutedSelectedV3{Reference: firewallipc.RoutedReferenceV3{Work: ref.Work, Lineage: ref.Lineage, Generation: strconv.FormatUint(ref.Generation, 10)}, Side: side})
	return e
}
func (a *RoutedRemoteAuthority) Match(ctx context.Context, p configpoc.RoutedSelectedPlanV1, side string) error {
	return a.selected(ctx, "match", p, side)
}
func (a *RoutedRemoteAuthority) Resume(ctx context.Context, p configpoc.RoutedSelectedPlanV1) error {
	if p.Resolution() != "before" && p.Resolution() != "target" {
		return configpoc.ErrRecovery
	}
	return a.selected(ctx, "resume", p, "")
}
func (a *RoutedRemoteAuthority) Arm(ctx context.Context, p configpoc.RoutedSelectedPlanV1) error {
	return a.selected(ctx, "arm", p, "")
}
func (a *RoutedRemoteAuthority) Apply(ctx context.Context, p configpoc.RoutedSelectedPlanV1) error {
	return a.selected(ctx, "apply", p, "")
}
func (a *RoutedRemoteAuthority) Confirm(ctx context.Context, p configpoc.RoutedSelectedPlanV1) error {
	return a.selected(ctx, "confirm", p, "")
}
func (a *RoutedRemoteAuthority) Recover(ctx context.Context, p configpoc.RoutedSelectedPlanV1) error {
	return a.selected(ctx, "recover", p, "")
}
func (a *RoutedRemoteAuthority) Bootstrap(ctx context.Context, p configpoc.RoutedSelectedPlanV1, started time.Time) error {
	if !p.Deadline().Equal(started.Add(10 * time.Second)) {
		return configpoc.ErrRecovery
	}
	return a.selected(ctx, "bootstrap", p, "")
}

var _ configpoc.RoutedAuthorityV1 = (*RoutedRemoteAuthority)(nil)

// RoutedRemoteIntegrityV3 uses the explicitly negotiated control capability.
// Transport failure closes this controller; it never reports an incomplete
// inspection as successful qualification.
type RoutedRemoteIntegrityV3 struct{ client *firewallipc.RoutedClientV3 }

func NewRoutedRemoteIntegrityV3(client *firewallipc.RoutedClientV3) (*RoutedRemoteIntegrityV3, error) {
	if client == nil || !client.IntegrityEnabled() {
		return nil, ErrIdentity
	}
	return &RoutedRemoteIntegrityV3{client: client}, nil
}
func (r *RoutedRemoteIntegrityV3) Attach(ctx context.Context, expected configpoc.SelectionReferenceV2) error {
	result, err := r.client.Call(ctx, "inspect", firewallipc.RoutedIntegrityV3{Mode: "attach", Selection: expected})
	if err != nil {
		return err
	}
	if result.Integrity.Selection != expected || result.Integrity.State != configpoc.IntegrityCompleteV1 {
		return configpoc.ErrRecovery
	}
	return nil
}
func (r *RoutedRemoteIntegrityV3) Inspect(ctx context.Context, expected configpoc.SelectionReferenceV2) (configpoc.IntegrityResultV1, error) {
	result, err := r.client.Call(ctx, "inspect", firewallipc.RoutedIntegrityV3{Mode: "check", Selection: expected})
	if err != nil {
		_ = r.client.Close()
		return configpoc.IntegrityResultV1{}, err
	}
	if result.Integrity.State == configpoc.IntegrityFencedV1 {
		_ = r.client.Close()
	}
	return result.Integrity, err
}

var _ configpoc.RuntimeIntegrityV1 = (*RoutedRemoteIntegrityV3)(nil)

func (r *RoutedRemoteIntegrityV3) IntegrityPublicationAllowedV1() bool {
	return r != nil && r.client.IntegrityPublicationAllowedV1()
}

func (r *RoutedRemoteIntegrityV3) IntegrityClosingAllowedV1() bool {
	return r != nil && r.client.IntegrityClosingAllowedV1()
}

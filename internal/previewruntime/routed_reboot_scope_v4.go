package previewruntime

import (
	"context"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

type RoutedRebootScopeBindingV4 RoutedFreshScopeBindingV3
type routedRebootScopeProofV4 interface {
	configpoc.RoutedRebootScopeAuthorityV4
	prepareSelected(context.Context, configpoc.RoutedActivationBundleV1, string) (configpoc.RoutedPreparationV1, error)
	verifyPlan(context.Context, configpoc.RoutedSelectedPlanV1) error
	Close() error
}

type routedRebootScopeRemoteV4 struct{ client *firewallipc.RoutedClientV3 }

func (r *routedRebootScopeRemoteV4) ProveRebootScope(ctx context.Context, work string) (configpoc.RoutedRebootScopeEvidenceV4, error) {
	if r == nil || r.client == nil || !r.client.RebootScopeEnabled() {
		return configpoc.RoutedRebootScopeEvidenceV4{}, ErrIdentity
	}
	result, err := r.client.Call(ctx, "reboot_scope", firewallipc.RoutedFreshScopeRequestV3{Work: work})
	return result.RebootScope, err
}

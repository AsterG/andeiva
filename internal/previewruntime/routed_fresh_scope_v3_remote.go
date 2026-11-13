package previewruntime

import (
	"context"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

type routedFreshScopeRemoteV3 struct{ client *firewallipc.RoutedClientV3 }

func (r *routedFreshScopeRemoteV3) ProveFreshScope(ctx context.Context, work string) (configpoc.RoutedFreshScopeEvidenceV3, error) {
	if r == nil || r.client == nil || !r.client.FreshScopeEnabled() {
		return configpoc.RoutedFreshScopeEvidenceV3{}, ErrIdentity
	}
	result, err := r.client.Call(ctx, "fresh_scope", firewallipc.RoutedFreshScopeRequestV3{Work: work})
	return result.FreshScope, err
}

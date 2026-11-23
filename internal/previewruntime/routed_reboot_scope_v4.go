package previewruntime

import (
	"context"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// routedBootLineageV5 comes from the root-authenticated helper bootstrap.
type routedBootLineageV5 struct {
	Node             string `json:"node"`
	DeploymentSHA256 string `json:"deployment_sha256"`
	LinksSHA256      string `json:"links_sha256"`
}

func (l routedBootLineageV5) digest() string {
	if !validHex(l.Node, 16) || !retirementHashV3(l.DeploymentSHA256) || !retirementHashV3(l.LinksSHA256) {
		return ""
	}
	return retirementDigestV3(marshal(l))
}

type RoutedRebootScopeBindingV4 struct {
	ReceiptSHA256 string
	NewIdentity   networkexecutor.OwnedNamespaceIdentity
	Lineage       *routedBootLineageV5 `json:"lineage,omitempty"`
}

func (b RoutedRebootScopeBindingV4) detached() RoutedRebootScopeBindingV4 {
	if b.Lineage != nil {
		lineage := *b.Lineage
		b.Lineage = &lineage
	}
	return b
}

func (b RoutedRebootScopeBindingV4) lineageDigest() string {
	if b.Lineage == nil {
		return ""
	}
	return b.Lineage.digest()
}

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

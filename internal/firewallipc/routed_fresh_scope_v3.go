package firewallipc

import (
	"context"
	"io"

	"github.com/AsterG/andeiva/internal/configpoc"
)

const RoutedFreshScopeCapabilityV3 = "routed_fresh_scope.v3"

type RoutedFreshScopeRequestV3 struct {
	Work string `json:"work"`
}
type RoutedFreshScopeResultV3 struct {
	Evidence configpoc.RoutedFreshScopeEvidenceV3 `json:"evidence"`
}

func (h RoutedHelloV3) HasCapability(name string) bool {
	for _, feature := range h.RequiredFeatures {
		if feature == name {
			return true
		}
	}
	return false
}

func validRoutedScopeCapabilitiesV3(features []string) bool {
	if len(features) <= 5 {
		return true
	}
	if len(features) == 6 {
		return features[5] == RoutedDHCPCapabilityV3 || features[5] == RoutedFreshScopeCapabilityV3 || features[5] == RoutedRebootScopeCapabilityV4
	}
	return len(features) == 7 && features[5] == RoutedDHCPCapabilityV3 && (features[6] == RoutedFreshScopeCapabilityV3 || features[6] == RoutedRebootScopeCapabilityV4)
}

func ConnectRoutedFreshScopeV3(ctx context.Context, conn io.ReadWriteCloser, run string, namespace uint64, dhcp bool) (*RoutedClientV3, error) {
	return connectRoutedCapabilitiesV3(ctx, conn, run, namespace, true, true, dhcp, true, false)
}
func (c *RoutedClientV3) FreshScopeEnabled() bool { return c != nil && c.freshScope }

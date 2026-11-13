package firewallipc

import (
	"context"
	"io"

	"github.com/AsterG/andeiva/internal/configpoc"
)

const RoutedRebootScopeCapabilityV4 = "routed_reboot_scope.v4"

type RoutedRebootScopeResultV4 struct {
	Evidence configpoc.RoutedRebootScopeEvidenceV4 `json:"evidence"`
}

func ConnectRoutedRebootScopeV4(ctx context.Context, conn io.ReadWriteCloser, run string, namespace uint64, dhcp bool) (*RoutedClientV3, error) {
	return connectRoutedCapabilitiesV3(ctx, conn, run, namespace, true, true, dhcp, false, true)
}
func (c *RoutedClientV3) RebootScopeEnabled() bool { return c != nil && c.rebootScope }

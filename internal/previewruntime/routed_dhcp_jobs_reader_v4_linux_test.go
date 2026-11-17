//go:build linux

package previewruntime

import (
	"context"
	"os"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestRoutedDHCPJobsV4RequiresOperationalReaderBeforeInstallingRestoreHook(t *testing.T) {
	network := &routedNetworkSelectorV4{}
	assembly := routedDHCPJobAssemblyV4{network: network, listeners: &routedEmptyListenersV3{}, client: &routedDHCPJobClientV4{}, target: &os.File{}, host: &os.File{}}
	for range 2 {
		if helper, err := newRoutedDHCPJobsHelperV4(context.Background(), assembly, &configpoc.RoutedSelectionReaderV2{}, nil, &routedTransportAuthorityV3{}, &routedIntegrityGateV3{}, 123); err != ErrIdentity || helper != nil || network.beforeRestore != nil {
			t.Fatal("missing action reader altered restore ownership", helper, err)
		}
	}
}

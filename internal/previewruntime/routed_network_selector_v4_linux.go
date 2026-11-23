//go:build linux

package previewruntime

import (
	"context"
	"os"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
)

func newOwnedRoutedNetworkSelectorV4(ctx context.Context, target, host *os.File, id networkexecutor.OwnedNamespaceIdentity, readerGID uint32, bindings []networkplan.Binding) (*routedNetworkSelectorV4, error) {
	return newRoutedNetworkSelectorV4(ctx, bindings, func(call context.Context, desired *networkplan.Revision) (routedNetworkDriverV4, *networkexecutor.LANBootstrapV3, error) {
		if call == nil || call.Err() != nil {
			return nil, nil, ErrUnavailable
		}
		if desired != nil {
			_, dhcp, err := routedNetworkProfileV4(*desired)
			if err != nil {
				return nil, nil, err
			}
			if dhcp {
				lan, err := networkexecutor.NewLANBootstrapInOwnedNamespaceV3(ctx, target, host, id, readerGID, *desired)
				if err != nil {
					return nil, nil, err
				}
				return lan, lan, nil
			}
		}
		base, err := networkexecutor.NewInOwnedNamespaceWithReader(ctx, target, host, id, readerGID)
		if err != nil {
			return nil, nil, err
		}
		return base, nil, nil
	})
}

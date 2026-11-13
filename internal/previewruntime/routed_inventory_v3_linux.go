//go:build linux

package previewruntime

import (
	"context"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

// The helper process already entered its supervisor-pinned gateway namespace.
// Each observation checks both process and executing thread; API-host discovery
// and configuration-derived inventory are deliberately absent.
func routedInventoryProviderV3(metadata Metadata) func(context.Context) (networkinventory.Snapshot, error) {
	return func(ctx context.Context) (networkinventory.Snapshot, error) {
		if ctx == nil || ctx.Err() != nil || metadata.ValidateRouted() != nil {
			return networkinventory.Snapshot{}, ErrIdentity
		}
		observe := func() error {
			process, e := namespaceID("/proc/self/ns/net")
			thread, te := namespaceID("/proc/thread-self/ns/net")
			if e != nil || te != nil || process != metadata.GatewayNamespace || thread != metadata.GatewayNamespace || process == metadata.HostNamespace {
				return ErrIdentity
			}
			return nil
		}
		if err := observe(); err != nil {
			return networkinventory.Snapshot{}, err
		}
		snapshot, err := networkinventory.Discover(ctx)
		if err != nil {
			return networkinventory.Snapshot{}, err
		}
		if err = observe(); err != nil || ctx.Err() != nil {
			return networkinventory.Snapshot{}, ErrIdentity
		}
		return snapshot, nil
	}
}

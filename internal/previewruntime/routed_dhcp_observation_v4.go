package previewruntime

import (
	"context"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// The callback reads only the authenticated owner channel. It cannot call back
// into runtime/gate/forwarding or mutate lease authority while lower locks hold.
func routedDHCPObservationSourceV4(owner networkexecutor.LeaseOwner, desired string, current func(context.Context) (RoutedDHCPOwnerFactV3, error)) func(context.Context) (networkexecutor.LeaseObservationV4, error) {
	return func(ctx context.Context) (networkexecutor.LeaseObservationV4, error) {
		if ctx == nil || ctx.Err() != nil || current == nil {
			return networkexecutor.LeaseObservationV4{}, ErrIdentity
		}
		x, err := current(ctx)
		if margin, ok := routedDHCPMarginV4(err); ok && x == (RoutedDHCPOwnerFactV3{}) && ctx.Err() == nil {
			marker, markerErr := networkexecutor.NewLeaseMarginObservationV4(owner, desired, margin.epoch, margin.address)
			if markerErr != nil {
				return networkexecutor.LeaseObservationV4{}, markerErr
			}
			return networkexecutor.LeaseObservationV4{Epoch: margin.epoch, Margin: marker}, nil
		}
		if err != nil || ctx.Err() != nil || x.Epoch == 0 || x.Fact.Owner != owner || x.Fact.Revoked || x.Fact.DesiredHash != desired {
			return networkexecutor.LeaseObservationV4{}, ErrIdentity
		}
		return networkexecutor.LeaseObservationV4{Epoch: x.Epoch, Fact: x.Fact}, nil
	}
}

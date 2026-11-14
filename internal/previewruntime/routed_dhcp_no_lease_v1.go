package previewruntime

// Only an authenticated live acquisition snapshot can produce this state.
// Epoch is a revocation watermark, never a usable lease or forwarding grant.
type routedDHCPNoLeaseV1 struct{ epoch uint64 }

type routedDHCPNoLeaseWireV1 struct {
	Version       int    `json:"version"`
	ObservedEpoch uint64 `json:"observed_epoch"`
}

func (routedDHCPNoLeaseV1) Error() string { return "live DHCP service without lease v1" }

func routedDHCPNoLeaseEpochV1(err error) (uint64, bool) {
	x, ok := err.(routedDHCPNoLeaseV1)
	return x.epoch, ok && x.epoch > 0
}

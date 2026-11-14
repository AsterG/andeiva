package previewruntime

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
)

const RoutedDHCPDeferredOwnerRoleV4 = "--andeiva-routed-dhcp-owner-deferred-v4"

// Only a correlated initial-wait frame from a live confirmed acquisition may
// produce this sentinel. Generic unavailability must never be promoted to it.
var errRoutedDHCPInitialWaitingV1 = errors.New("initial DHCP acquisition pending v1")

// This profile identifies the trusted producer, not its future dhcpcd child.
// Root authenticates the binding and inherited descriptors before helper boot.
type RoutedDHCPDeferredBindingV4 struct {
	Version                            int
	MountNamespace, HostMountNamespace uint64
	Owner                              networkexecutor.LeaseOwner
	Desired                            networkplan.Revision
}
type routedDHCPDeferredBindingWireV4 struct {
	Version            int                       `json:"version"`
	MountNamespace     uint64                    `json:"mount_namespace"`
	HostMountNamespace uint64                    `json:"host_mount_namespace"`
	Owner              routedDHCPOwnerIdentityV3 `json:"owner"`
	Desired            networkplan.Revision      `json:"desired"`
}

func (b RoutedDHCPDeferredBindingV4) MarshalJSON() ([]byte, error) {
	return json.Marshal(routedDHCPDeferredBindingWireV4{b.Version, b.MountNamespace, b.HostMountNamespace, routedDHCPOwnerIdentityV3(b.Owner), b.Desired})
}
func (b *RoutedDHCPDeferredBindingV4) UnmarshalJSON(raw []byte) error {
	var w routedDHCPDeferredBindingWireV4
	if routedDHCPOwnerDecodeV3(raw, &w) != nil {
		return ErrIdentity
	}
	x := RoutedDHCPDeferredBindingV4{w.Version, w.MountNamespace, w.HostMountNamespace, networkexecutor.LeaseOwner(w.Owner), w.Desired}
	if !routedDHCPDeferredBindingValidV4(x) {
		return ErrIdentity
	}
	*b = x
	return nil
}
func routedDHCPDeferredBindingValidV4(b RoutedDHCPDeferredBindingV4) bool {
	n, err := networkexecutor.CanonicalLANBootstrapPlanV3(b.Desired)
	boot, e := canonicalBoot([]byte(b.Owner.BootID))
	return b.Version == 4 && err == nil && n.Hash == b.Desired.Hash && e == nil && boot == b.Owner.BootID && b.Owner.Namespace > 0 && b.Owner.PID > 1 && b.Owner.PID <= math.MaxInt32 && b.Owner.StartTicks > 0 && ValidRun(b.Owner.RunID) && ValidRun(b.Owner.Incarnation) && b.MountNamespace > 0 && b.HostMountNamespace > 0 && b.MountNamespace != b.HostMountNamespace
}
func cloneRoutedDHCPDeferredBindingV4(b RoutedDHCPDeferredBindingV4) (RoutedDHCPDeferredBindingV4, error) {
	raw, err := json.Marshal(b)
	var out RoutedDHCPDeferredBindingV4
	if err != nil || routedDHCPOwnerDecodeV3(raw, &out) != nil {
		return out, ErrIdentity
	}
	return out, nil
}

// No acquisition pidfd exists before Activate. Only the producer capability is
// inherited; root and the producer independently pin the actual child later.
type RoutedDHCPDeferredFilesV4 struct{ Request, Reply, ProducerPIDFD *os.File }

func (f RoutedDHCPDeferredFilesV4) Close() error { return f.transport().Close() }
func (f RoutedDHCPDeferredFilesV4) transport() RoutedDHCPOwnerFilesV3 {
	return RoutedDHCPOwnerFilesV3{Request: f.Request, Reply: f.Reply, RolePIDFD: f.ProducerPIDFD}
}

type RoutedDHCPAcquisitionIdentityV4 struct {
	PID        int32  `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
}

func (a RoutedDHCPAcquisitionIdentityV4) valid(producer int64) bool {
	return producer > 1 && producer <= math.MaxInt32 && a.PID > 1 && int64(a.PID) != producer && a.StartTicks > 0
}

type routedDHCPDeferredReplyV4 struct {
	Version        int                              `json:"version"`
	Incarnation    string                           `json:"incarnation"`
	Sequence       uint64                           `json:"sequence"`
	Unavailable    bool                             `json:"unavailable,omitempty"`
	WaitingVersion *int                             `json:"waiting_version,omitempty"`
	Acquisition    *RoutedDHCPAcquisitionIdentityV4 `json:"acquisition,omitempty"`
	Lease          *routedDHCPOwnerLeaseV3          `json:"lease,omitempty"`
}
type routedDHCPDeferredControlV4 struct {
	Version     int                              `json:"version"`
	Incarnation string                           `json:"incarnation"`
	Sequence    uint64                           `json:"sequence"`
	Operation   string                           `json:"operation"`
	Acquisition *RoutedDHCPAcquisitionIdentityV4 `json:"acquisition,omitempty"`
}
type routedDHCPDeferredEventV4 struct {
	Version            int                              `json:"version"`
	Incarnation        string                           `json:"incarnation"`
	ProducerPID        int32                            `json:"producer_pid"`
	ProducerStartTicks uint64                           `json:"producer_start_ticks"`
	Phase              string                           `json:"phase"`
	Acquisition        *RoutedDHCPAcquisitionIdentityV4 `json:"acquisition,omitempty"`
}

type RoutedDHCPDeferredReaderV4 struct{ reader *RoutedDHCPOwnerReaderV3 }

func (r *RoutedDHCPDeferredReaderV4) Current(ctx context.Context) (RoutedDHCPOwnerFactV3, error) {
	if r == nil {
		return RoutedDHCPOwnerFactV3{}, ErrIdentity
	}
	return r.reader.Current(ctx)
}
func (r *RoutedDHCPDeferredReaderV4) Close() error {
	if r == nil {
		return nil
	}
	return r.reader.Close()
}

func newRoutedDHCPDeferredReaderV4(files RoutedDHCPDeferredFilesV4, b RoutedDHCPDeferredBindingV4, alive func() bool, now func() (int64, error)) (*RoutedDHCPDeferredReaderV4, error) {
	b, err := cloneRoutedDHCPDeferredBindingV4(b)
	if err != nil {
		return nil, err
	}
	r := &RoutedDHCPOwnerReaderV3{gate: make(chan struct{}, 1), files: files.transport(), scanner: routedDHCPOwnerScannerV3(files.Reply), profile: 4, incarnation: b.Owner.Incarnation, alive: alive, now: now}
	var acquisition RoutedDHCPAcquisitionIdentityV4
	initial := true
	r.decode = func(raw []byte, q routedDHCPOwnerRequestV3) (*routedDHCPOwnerLeaseV3, bool, error) {
		var reply routedDHCPDeferredReplyV4
		if routedDHCPOwnerDecodeV3(raw, &reply) != nil || q.Version != 4 || reply.Version != 4 || reply.Incarnation != q.Incarnation || reply.Sequence != q.Sequence {
			return nil, false, ErrIdentity
		}
		if reply.WaitingVersion != nil {
			if *reply.WaitingVersion != 1 || !initial || reply.Unavailable || reply.Lease != nil || reply.Acquisition == nil || !reply.Acquisition.valid(int64(b.Owner.PID)) || acquisition != (RoutedDHCPAcquisitionIdentityV4{}) && acquisition != *reply.Acquisition {
				return nil, false, ErrIdentity
			}
			acquisition = *reply.Acquisition
			return nil, false, errRoutedDHCPInitialWaitingV1
		}
		initial = false
		if reply.Unavailable {
			if reply.Lease != nil || reply.Acquisition != nil {
				return nil, false, ErrIdentity
			}
			return nil, true, nil
		}
		if reply.Lease == nil || reply.Acquisition == nil || !reply.Acquisition.valid(int64(b.Owner.PID)) || acquisition != (RoutedDHCPAcquisitionIdentityV4{}) && acquisition != *reply.Acquisition || reply.Lease.Event.PID != int(reply.Acquisition.PID) {
			return nil, false, ErrIdentity
		}
		acquisition = *reply.Acquisition
		return reply.Lease, false, nil
	}
	r.accept = func(l routedDHCPOwnerLeaseV3, now int64) (RoutedDHCPOwnerFactV3, error) {
		return r.facts.acceptBound(l, now, routedDHCPDeferredBindingValidV4(b) && acquisition.valid(int64(b.Owner.PID)), b.Owner, b.Desired, int(acquisition.PID))
	}
	return &RoutedDHCPDeferredReaderV4{r}, nil
}

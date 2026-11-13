package firewallipc

import (
	"context"
	"errors"
	"io"
	"reflect"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

const RoutedDHCPCapabilityV3 = "routed_dhcp_selected.v3"

// This versioned error is a no-effect initial wait, never a grant or readiness.
// Older peers reject the unknown code; no compatibility fallback is permitted.
var ErrRoutedDHCPWaitingV1 = errors.New("ANDEIVA_ROUTED_DHCP_WAITING_V1")

// Requests carry correlation only. Neither owner identity, route, lease time,
// epoch nor a serialized selected plan can be supplied by the controller.
type RoutedDHCPRequestV3 struct {
	Work     string                               `json:"work,omitempty"`
	Snapshot string                               `json:"snapshot,omitempty"`
	State    networkexecutor.LeaseSelectedStateV3 `json:"state,omitempty"`
}

type RoutedDHCPGrantV3 struct {
	Epoch    uint64                                  `json:"epoch,string"`
	Snapshot networkexecutor.LeaseSelectedSnapshotV3 `json:"snapshot"`
}

func RoutedDHCPVerbV3(verb string) bool {
	switch verb {
	case "dhcp_begin", "dhcp_current", "dhcp_verify", "dhcp_apply", "dhcp_open", "dhcp_withdraw", "dhcp_live", "dhcp_retire":
		return true
	default:
		return false
	}
}

func decodeRoutedDHCPRequestV3(verb string, raw []byte) (RoutedDHCPRequestV3, error) {
	var p RoutedDHCPRequestV3
	var fields []string
	switch verb {
	case "dhcp_begin", "dhcp_current", "dhcp_retire":
	case "dhcp_verify":
		fields = []string{"snapshot", "state"}
	case "dhcp_apply", "dhcp_open", "dhcp_withdraw", "dhcp_live":
		fields = []string{"work"}
	default:
		return p, ErrChannel
	}
	if exactRoutedV3(raw, &p, fields) != nil {
		return p, ErrChannel
	}
	switch verb {
	case "dhcp_verify":
		if !hashV2(p.Snapshot) || (p.State != networkexecutor.LeaseSelectedBaselineV3 && p.State != networkexecutor.LeaseSelectedTargetV3) {
			return p, ErrChannel
		}
	case "dhcp_apply", "dhcp_open", "dhcp_withdraw", "dhcp_live":
		if !hashV2(p.Work) {
			return p, ErrChannel
		}
	}
	return p, nil
}

func decodeRoutedDHCPReplyV3(verb string, raw []byte) (RoutedDHCPGrantV3, error) {
	var g RoutedDHCPGrantV3
	if verb == "dhcp_current" || verb == "dhcp_begin" {
		if exactRoutedV3(raw, &g, []string{"epoch", "snapshot"}) != nil || g.Epoch == 0 {
			return g, ErrChannel
		}
		s, err := networkexecutor.CanonicalLeaseSelectedSnapshotV3(g.Snapshot)
		if err != nil || !reflect.DeepEqual(s, g.Snapshot) {
			return g, ErrChannel
		}
		return g, nil
	}
	var empty struct{}
	if !RoutedDHCPVerbV3(verb) || exactRoutedV3(raw, &empty, nil) != nil {
		return g, ErrChannel
	}
	return g, nil
}

func ConnectRoutedDHCPV3(ctx context.Context, conn io.ReadWriteCloser, run string, ns uint64) (*RoutedClientV3, error) {
	return connectRoutedCapabilitiesV3(ctx, conn, run, ns, true, true, true, false, false)
}
func (c *RoutedClientV3) DHCPEnabled() bool { return c != nil && c.dhcp }

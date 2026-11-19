package routedactivation

import (
	"bytes"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

type localIngress struct {
	network *networkplan.Revision
	server  *routedmodel.Revision
}

// Local controls follow the exact selected routed table, including the
// compiler-derived deny state that permits WAN acquisition during handover.
func routedLocalIngress(state TableStateV1, deps DependenciesV1) (localIngress, error) {
	if state.Presence == Absent && state.Revision == nil {
		return localIngress{}, nil
	}
	if state.Presence != Present || state.Revision == nil || state.Revision.Config.Routed == nil {
		return localIngress{}, ErrState
	}
	r, err := configpoc.CanonicalRouted(state.Revision.Config)
	if err != nil || r.Hash != state.Revision.Hash || r.Config.Routed.Network.Hash != deps.Network.Hash {
		return localIngress{}, ErrState
	}
	n, err := networkplan.Canonical(deps.Network.Config)
	if err != nil || n.Hash != deps.Network.Hash {
		return localIngress{}, ErrState
	}
	ingress := localIngress{network: &n}
	if cfg := r.Config.Routed.DHCPServer; cfg != nil && cfg.Enabled {
		policy, err := routedmodel.Canonical(*r.Config.Routed)
		if err != nil {
			return localIngress{}, ErrState
		}
		ingress.server = &policy
	}
	return ingress, nil
}

func (i localIngress) compile(local *configpoc.Revision, neighbors []localnft.NeighborLink) (localnft.Artifact, error) {
	if local == nil || local.Config.LocalServices == nil {
		return localnft.Artifact{}, ErrState
	}
	if i.server != nil {
		return localnft.CompileForRoutedPolicy(*local.Config.LocalServices, neighbors, *i.server)
	}
	return localnft.CompileForNetwork(*local.Config.LocalServices, neighbors, i.network)
}

func (i localIngress) sameControls(other localIngress, local *configpoc.Revision, neighbors []localnft.NeighborLink) (bool, error) {
	// Preserve the existing WAN/network replacement boundary.
	if (i.network == nil) != (other.network == nil) || (i.network != nil && i.network.Hash != other.network.Hash) {
		return false, nil
	}
	if i.server == nil || other.server == nil {
		return i.server == nil && other.server == nil, nil
	}
	if i.server.Hash == other.server.Hash {
		return true, nil
	}
	// Lease-pool and forwarding edits can keep the same Local-In rules.
	before, err := i.compile(local, neighbors)
	if err != nil {
		return false, err
	}
	after, err := other.compile(local, neighbors)
	if err != nil {
		return false, err
	}
	return bytes.Equal(before.Create, after.Create), nil
}

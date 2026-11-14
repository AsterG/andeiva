package routedactivation

import (
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkplan"
)

// The local control rule follows the exact selected routed table, including
// compiler-derived deny states. An absent routed table has no acquisition rule.
func acquisitionNetwork(state TableStateV1, deps DependenciesV1) (*networkplan.Revision, error) {
	if state.Presence == Absent && state.Revision == nil {
		return nil, nil
	}
	if state.Presence != Present || state.Revision == nil || state.Revision.Config.Routed == nil {
		return nil, ErrState
	}
	r, err := configpoc.CanonicalRouted(state.Revision.Config)
	if err != nil || r.Hash != state.Revision.Hash || r.Config.Routed.Network.Hash != deps.Network.Hash {
		return nil, ErrState
	}
	n, err := networkplan.Canonical(deps.Network.Config)
	if err != nil || n.Hash != deps.Network.Hash {
		return nil, ErrState
	}
	return &n, nil
}

func sameAcquisitionNetwork(a, b *networkplan.Revision) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Hash == b.Hash
}

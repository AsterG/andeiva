// Package routednft implements the isolated IPv4 routed firewall adapter.
package routednft

import (
	"github.com/AsterG/andeiva/internal/nftengine"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

const TableName = "andeiva_routed_alpha"
const MaxRules = routedmodel.MaxRules
const MaxObservation = 1 << 20

var ErrPolicy = nftengine.ErrPolicy
var ErrObservation = nftengine.ErrObservation

type Ports = routedmodel.Ports
type Path = routedmodel.Path
type Rule = routedmodel.Rule
type Masquerade = routedmodel.Masquerade
type Policy = routedmodel.Policy
type Revision = routedmodel.Revision

func Canonical(input Policy) (Revision, error) {
	r, err := routedmodel.Canonical(input)
	if err != nil {
		return Revision{}, ErrPolicy
	}
	return r, nil
}
func ruleMark(r Rule) uint32 { return routedmodel.RuleMark(r) }

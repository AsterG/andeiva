package routedactivation

import (
	"context"
	"errors"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

type leaseObservationNetworkV4 interface {
	VerifyObservationV4(context.Context) error
}

// The network witness alone is insufficient: only this private wrapper records
// that the selected target's nft tables and listeners were also read back.
type closedLeaseObservationV4 struct {
	cause   error
	running string
}

func (*closedLeaseObservationV4) Error() string   { return "ANDEIVA_CLOSED_LEASE_OBSERVATION_V4" }
func (e *closedLeaseObservationV4) Unwrap() error { return e.cause }

// MatchesClosedLeaseObservationV4 proves only closure/reconciliation context.
// It never proves owned references or permission to open forwarding.
func MatchesClosedLeaseObservationV4(err error, expected networkexecutor.LeaseFact, running string) bool {
	var witness *closedLeaseObservationV4
	return errors.As(err, &witness) && witness != nil && running != "" && witness.running == running && networkexecutor.MatchesLeaseObservationPendingV4(witness.cause, expected)
}

// matchesObservationV4 is exclusively an observation lane. All preparation,
// effects and owned-reference checks continue to use the legacy matcher.
func (e *Engine) matchesObservationV4(ctx context.Context, owned OwnedV1, deps DependenciesV1) (bool, error) {
	observer, enabled := e.network.(leaseObservationNetworkV4)
	if !enabled || owned.NetworkState != Configured {
		return e.matches(ctx, owned, deps), nil
	}
	if ctx.Err() != nil {
		nativeDHCPObservationFailureV4("context")
		return false, ErrState
	}
	pending := observer.VerifyObservationV4(ctx)
	// Only the concrete source witness qualifies; generic errors wrapping or
	// joining it remain failures and cannot mint an Engine wrapper.
	if pending != nil && !networkexecutor.IsLeaseObservationPendingV4(pending) {
		nativeDHCPObservationFailureV4("network_generic")
		return false, ErrState
	}
	ingress, err := routedLocalIngress(owned.RoutedFirewall, deps)
	if err != nil {
		nativeDHCPObservationFailureV4("acquisition_network")
		return false, ErrState
	}
	for table, state := range tables(owned) {
		if !e.tableMatches(ctx, Table(table), state, deps, ingress) {
			nativeDHCPObservationTableFailureV4(Table(table))
			return false, ErrState
		}
	}
	if !e.listenersMatch(ctx, owned.LocalServices, deps) || ctx.Err() != nil {
		nativeDHCPObservationFailureV4("listeners_or_context")
		return false, ErrState
	}
	return pending == nil, pending
}

package adminauth

import "github.com/AsterG/andeiva/internal/authobservations"

// NewWithAnonymousObservations is an explicit constructor admission, not a
// runtime switch. The selected observation store requires a trusted runtime
// compatibility/isolation guard. New remains byte-for-byte legacy audit behavior.
func NewWithAnonymousObservations(accounts []Account, audit func(Event) error, observations *authobservations.Store) (*Manager, error) {
	if observations == nil || observations.Admitted() != nil {
		return nil, ErrUnavailable
	}
	m, err := New(accounts, audit)
	if err != nil {
		return nil, err
	}
	m.observations = observations
	return m, nil
}

// AnonymousObservations is a read-only projection for a freshly authenticated
// administrator. It adds no route and grants no write, export or deletion power.
func (m *Manager) AnonymousObservations(token string) (authobservations.Report, error) {
	id, err := m.Authenticate(token)
	if err != nil {
		return authobservations.Report{}, err
	}
	if id.Role != "admin" {
		return authobservations.Report{}, ErrDenied
	}
	if m.observations == nil {
		return authobservations.Report{}, ErrUnavailable
	}
	return m.observations.Report(), nil
}

package configpoc

// currentLegacyProjectionV2 is a read-only view for exact retained v1 replays.
// Its counter is persisted per domain; it is never derived from global state.
// The caller holds the store lock and preserves the original receipt generation.
func (s *v2Store) currentLegacyProjectionV2(domain string, imported Snapshot) (Snapshot, error) {
	if s.state.Configuration == nil {
		return clone(imported), nil
	}
	state := s.state.Configuration
	if !validV2Configuration(state) || s.state.Generation == 0 {
		return Snapshot{}, errV2Unavailable
	}
	current := state.Firewall
	if domain == "local_services" {
		current = state.LocalServices
	} else if domain != "firewall" {
		return Snapshot{}, errV2Invalid
	}
	if current.Generation < imported.Generation {
		return Snapshot{}, errV2Unavailable
	}
	view := Snapshot{Generation: current.Generation, Running: clone(current.Running), Startup: clone(current.Startup), LastGood: clone(current.LastGood), Revoked: clone(imported.Revoked), RecoveryRequired: state.RecoveryRequired || state.Intent != nil}
	if current.Candidate != nil {
		view.Candidate = &Candidate{Owner: current.Candidate.Owner, Base: current.Candidate.Base, Revision: clone(current.Candidate.Revision)}
	}
	if pending := state.Pending; pending != nil && pending.Domain == domain {
		var previous v2Configuration
		if s.readObject(pending.Previous, &previous) != nil || !validV2Configuration(&previous) {
			return Snapshot{}, errV2Unavailable
		}
		prior := previous.Firewall.Running
		if domain == "local_services" {
			prior = previous.LocalServices.Running
		}
		view.Pending = &Pending{Owner: pending.Owner, Lease: pending.Lease, Deadline: pending.Deadline, Previous: clone(prior)}
	}
	return view, nil
}

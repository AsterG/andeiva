package configpoc

// managedRequest validates all caller-controlled semantics before even querying
// the privileged engine. Execute repeats checks while performing state changes;
// both run under the same lock, including autonomous timeout recovery.
func (s *Service) managedRequest(p Principal, r Request) error {
	if r.Operation != OpStage && r.Config != nil {
		return ErrInvalid
	}
	if r.Operation != OpCommit && r.Operation != OpRollback && r.ConfirmFor != 0 {
		return ErrInvalid
	}
	if r.Operation != OpConfirm && r.Operation != OpRollback && r.Target != "" {
		return ErrInvalid
	}
	snap := s.state.Snapshot
	switch r.Operation {
	case OpStage:
		if r.Config == nil {
			return ErrInvalid
		}
		if _, err := Canonical(*r.Config); err != nil {
			return err
		}
		if snap.Candidate != nil && snap.Candidate.Owner != p.ID {
			return ErrConflict
		}
	case OpValidate, OpCommit:
		if snap.Candidate == nil || snap.Candidate.Owner != p.ID {
			return ErrDenied
		}
		if snap.Candidate.Base != snap.Running.Hash {
			return ErrConflict
		}
		if r.Operation == OpCommit && r.ConfirmFor == 0 && localServicesChanged(snap.Running.Config, snap.Candidate.Revision.Config) {
			return ErrInvalid
		}
	case OpConfirm:
		if snap.Pending == nil {
			return ErrInvalid
		}
		if snap.Pending.Owner != p.ID {
			return ErrDenied
		}
		if r.Target != snap.Running.Hash {
			return ErrInvalid
		}
	case OpRollback:
		if !validHash(r.Target) {
			return ErrInvalid
		}
		target, ok, err := s.historical(r.Target)
		if err != nil {
			return err
		}
		if !ok || !validRollbackWindow(snap.Running.Config, target.Config, r.ConfirmFor) {
			return ErrInvalid
		}
		if snap.Candidate != nil && snap.Candidate.Owner != p.ID {
			return ErrConflict
		}
	case OpSave:
	default:
		return ErrInvalid
	}
	return nil
}

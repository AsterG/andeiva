package configpoc

// RevisionEntry is a bounded immutable view of a durably confirmed revision.
type RevisionEntry struct {
	Sequence uint64   `json:"sequence"`
	Revision Revision `json:"revision"`
}

func (s *Service) historical(hash string) (Revision, bool) {
	for i := len(s.store.records) - 1; i >= 0; i-- {
		r := s.store.records[i]
		if r.State.Intent == nil && r.State.Snapshot.Pending == nil && !r.State.Snapshot.RecoveryRequired && r.State.Snapshot.Running.Hash == hash {
			return clone(r.State.Snapshot.Running), true
		}
	}
	return Revision{}, false
}

// Revisions returns newest distinct confirmed Running revisions. Candidate and
// provisional revisions are never selectable rollback targets.
func (s *Service) Revisions(p Principal, before uint64, limit int) ([]RevisionEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.authorized(p, "history") {
		return nil, ErrDenied
	}
	if s.closed || s.halted {
		return nil, ErrRecovery
	}
	if limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	out := []RevisionEntry{}
	for i := len(s.store.records) - 1; i >= 0 && len(out) < limit; i-- {
		r := s.store.records[i]
		if r.State.Intent != nil || r.State.Snapshot.Pending != nil || r.State.Snapshot.RecoveryRequired {
			continue
		}
		hash := r.State.Snapshot.Running.Hash
		if seen[hash] {
			continue
		}
		seen[hash] = true
		if before != 0 && r.Audit.Sequence >= before {
			continue
		}
		out = append(out, RevisionEntry{r.Audit.Sequence, clone(r.State.Snapshot.Running)})
	}
	return out, nil
}

package configpoc

// RevisionEntry is a bounded immutable view of a durably confirmed revision.
type RevisionEntry struct {
	Sequence uint64   `json:"sequence"`
	Revision Revision `json:"revision"`
}

func (s *Service) historical(hash string) (Revision, bool, error) {
	for i := len(s.store.records) - 1; i >= 0; i-- {
		r := s.store.records[i]
		if r.confirmed && r.runningHash == hash {
			record, err := s.store.read(uint64(i + 1))
			if err != nil {
				return Revision{}, false, err
			}
			return clone(record.State.Snapshot.Running), true, nil
		}
	}
	return Revision{}, false, nil
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
		if !r.confirmed {
			continue
		}
		hash := r.runningHash
		if seen[hash] {
			continue
		}
		seen[hash] = true
		sequence := uint64(i + 1)
		if before != 0 && sequence >= before {
			continue
		}
		record, err := s.store.read(sequence)
		if err != nil {
			return nil, err
		}
		out = append(out, RevisionEntry{sequence, clone(record.State.Snapshot.Running)})
	}
	return out, nil
}

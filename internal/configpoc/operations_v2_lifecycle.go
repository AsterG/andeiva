package configpoc

import "time"

func (s *v2Store) changeSubject(id, login, credentialRevision string, retire bool, now time.Time) (v2Subject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked || now.Before(s.state.Clock) {
		return v2Subject{}, errV2Unavailable
	}
	if login == "" || len(login) > 128 || !v2HashPattern.MatchString(credentialRevision) {
		return v2Subject{}, errV2Invalid
	}
	st := clone(s.state)
	index := -1
	for i, sub := range st.Subjects {
		if sub.ID == id {
			index = i
			if sub.Retired {
				return v2Subject{}, errV2NotFound
			}
		}
		if sub.ID != id && !sub.Retired && sub.Login == login {
			return v2Subject{}, errV2Invalid
		}
	}
	if id == "" {
		if retire || uint64(len(st.Subjects)) >= st.SubjectSlots || st.SubjectSequence == ^uint64(0) {
			return v2Subject{}, errV2Limited
		}
		var err error
		id, err = v2ID("subject", st.SubjectSequence+1)
		if err != nil {
			return v2Subject{}, err
		}
		index = len(st.Subjects)
		st.SubjectSequence++
		st.Subjects = append(st.Subjects, v2Subject{ID: id})
	} else if index < 0 {
		return v2Subject{}, errV2NotFound
	}
	st.Subjects[index].Login = login
	st.Subjects[index].CredentialRevision = credentialRevision
	st.Subjects[index].Retired = retire
	if retire {
		// Close admission atomically with revocation, but do not infer outcomes
		// for accepted or in-flight work. Their reservations survive until the
		// ordinary expiry or independently verified recovery path resolves them.
		for i := range st.Namespaces {
			if st.Namespaces[i].Subject == id {
				st.Namespaces[i].Closed = true
			}
		}
	}
	st.Clock = now.UTC()
	if err := s.publish(st); err != nil {
		return v2Subject{}, err
	}
	return st.Subjects[index], nil
}

// Closing and expiry finalize only accepted operations. Pending/uncertain and
// pinned final operations retain their reservations and require reconciliation.
func (s *v2Store) closeNamespace(subject, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeNamespaceLocked(subject, id, now)
}

func (s *v2Store) closeNamespaceLocked(subject, id string, now time.Time) error {
	if s.blocked || now.Before(s.state.Clock) {
		return errV2Unavailable
	}
	i := s.namespaceIndex(subject, id)
	if i < 0 || !s.subject(subject) {
		return errV2NotFound
	}
	if s.state.Namespaces[i].Closed {
		return nil
	}
	st := clone(s.state)
	st.Namespaces[i].Closed = true
	st.Clock = now.UTC()
	closingRestore, err := s.closingBatchAllowanceLocked(st.Namespaces[i].ClosingOpen, nil)
	if err != nil {
		return err
	}
	defer closingRestore()
	for _, opID := range namespaceOpenIDsV2(st.Namespaces[i]) {
		op, err := s.lookupLocked(subject, opID)
		if err != nil {
			return err
		}
		if op.State == "accepted" {
			if err = s.withoutEffects(&st, op, "ANDEIVA_NAMESPACE_CLOSED", now); err != nil {
				s.blocked = true
				return err
			}
		}
	}
	restore, err := s.releasedAllowance(&st)
	if err != nil {
		return err
	}
	defer restore()
	return s.publish(st)
}

func (s *v2Store) withoutEffects(st *v2State, op v2Operation, code string, now time.Time) error {
	if st == nil || op.State != "accepted" {
		return errV2Invalid
	}
	closingRestore, err := s.closingOperationAllowanceLocked(op)
	if err != nil {
		return err
	}
	defer closingRestore()
	v2Release(st, op)
	restore, err := s.releasedAllowance(st)
	if err != nil {
		return err
	}
	defer restore()
	completed := now.UTC()
	until := completed.Add(30 * 24 * time.Hour)
	audit, err := s.object(struct{ Format, Operation, Code string }{v2Format, op.ID, code})
	if err != nil {
		return err
	}
	op.State = "final"
	op.Completed = &completed
	op.RetainUntil = &until
	op.Pinned = false
	result := "expired_without_effects"
	if code == "ANDEIVA_NAMESPACE_CLOSED" {
		result = "rejected"
	}
	op.Outcome = &v2Outcome{Code: result, ErrorCode: code, Generation: st.Generation, AuditHash: audit}
	return s.putOperation(st, op)
}

func (s *v2Store) expire(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked || now.Before(s.state.Clock) {
		return errV2Unavailable
	}
	st := clone(s.state)
	changed := false
	children := []v2ClosingOpen{}
	for _, ns := range s.state.Namespaces {
		children = append(children, ns.ClosingOpen...)
	}
	closingRestore, err := s.closingBatchAllowanceLocked(children, &now)
	if err != nil {
		return err
	}
	defer closingRestore()
	for _, ns := range s.state.Namespaces {
		for _, id := range namespaceOpenIDsV2(ns) {
			op, err := s.lookupRetained(ns.Subject, id)
			if err != nil {
				return err
			}
			if op.State == "accepted" && !now.Before(op.ExecuteBefore) {
				if err = s.withoutEffects(&st, op, "ANDEIVA_OPERATION_EXPIRED", now); err != nil {
					s.blocked = true
					return err
				}
				changed = true
			}
		}
	}
	if !changed {
		return nil
	}
	st.Clock = now.UTC()
	restore, err := s.releasedAllowance(&st)
	if err != nil {
		return err
	}
	defer restore()
	return s.publish(st)
}

// Release requires a linked coordinator reconciliation record, not a timeout
// guess. It is internal; transport authorization is deliberately unavailable.
func (s *v2Store) releasePin(subject, id, reconciliation string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked || now.Before(s.state.Clock) {
		return errV2Unavailable
	}
	op, err := s.lookupLocked(subject, id)
	if err != nil {
		return err
	}
	linked, err := s.lookupLocked(subject, reconciliation)
	if err != nil || linked.State != "final" || linked.Request.Kind != OpConfirm || linked.Request.Origin != id || linked.Domain != op.Domain || linked.Outcome == nil || linked.Outcome.Code != "applied" {
		return errV2Invalid
	}
	if op.State != "final" {
		return errV2Uncertain
	}
	if !op.Pinned {
		return nil
	}
	closingRestore, err := s.closingOperationAllowanceLocked(linked)
	if err != nil {
		return err
	}
	defer closingRestore()
	st := clone(s.state)
	op.Pinned = false
	v2Release(&st, op)
	restore, err := s.releasedAllowance(&st)
	if err != nil {
		return err
	}
	defer restore()
	st.Clock = now.UTC()
	if err = s.putOperation(&st, op); err != nil {
		s.blocked = true
		return err
	}
	return s.publish(st)
}

// Retirement changes only the current catalogue view after the promised window.
// Immutable history/audit and all older objects remain retained: no reclamation
// or export acknowledgement capability is implemented by these foundations.
func (s *v2Store) retire(subject, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked || now.Before(s.state.Clock) {
		return errV2Unavailable
	}
	op, err := s.lookupRetained(subject, id)
	if err != nil {
		return err
	}
	if op.State != "final" || op.Pinned || op.RetainUntil == nil || now.Before(*op.RetainUntil) {
		return errV2Invalid
	}
	for _, credit := range s.state.ClosingCredits {
		if credit.Origin == id || credit.Child == id {
			return errV2Limited
		}
	}
	wasRetired := op.Retired
	op.Retired = true
	st := clone(s.state)
	if st.RecoveryReserveVersion == 1 && !wasRetired {
		if op.ClosingCredit != "" {
			if st.OccupiedClosing == 0 {
				return errV2Unavailable
			}
			st.OccupiedClosing--
		} else {
			if st.OccupiedOrdinary == 0 {
				return errV2Unavailable
			}
			st.OccupiedOrdinary--
		}
	}
	st.Clock = now.UTC()
	if err = s.putOperation(&st, op); err != nil {
		s.blocked = true
		return err
	}
	return s.publish(st)
}

// Only an explicitly retired, unpinned catalogue view can leave the hot
// namespace registry. Protected immutable objects remain retained on disk.
func (s *v2Store) retireNamespace(subject, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked || now.Before(s.state.Clock) {
		return errV2Unavailable
	}
	i := s.namespaceIndex(subject, id)
	if i < 0 {
		return errV2NotFound
	}
	ns := s.state.Namespaces[i]
	if !ns.Closed || len(namespaceOpenIDsV2(ns)) != 0 || now.Before(ns.AdmitUntil.Add(30*24*time.Hour)) {
		return errV2Invalid
	}
	for _, credit := range s.state.ClosingCredits {
		if credit.Namespace == id || credit.ChildNamespace == id || credit.ClosingNamespace == id {
			return errV2Limited
		}
	}
	if s.state.RecoveryReserveVersion == 1 {
		if err := s.visitOrdinaryIndexV2(s.state.Index, 2, 0, func(op v2Operation) error {
			if op.Namespace == id && (!op.Retired || op.State != "final" || op.Pinned || op.RetainUntil == nil || now.Before(*op.RetainUntil)) {
				return errV2Limited
			}
			return nil
		}); err != nil {
			return err
		}
		if err := s.closingIndexVisit(s.state.ClosingIndexRoot, 0, func(op v2Operation) error {
			if op.Namespace == id {
				return errV2Limited
			}
			return nil
		}); err != nil {
			return err
		}
	} else {
		count := s.state.HighWater
		if count > s.state.LiveSlots {
			count = s.state.LiveSlots
		}
		for offset := uint64(0); offset < count; offset++ {
			seq := s.state.HighWater - offset
			hash, err := s.indexGet(s.state.Index, seq)
			if err != nil {
				return err
			}
			var op v2Operation
			if s.readObject(hash, &op) != nil || !s.validOperation(op) {
				return errV2Unavailable
			}
			if op.Namespace == id && (!op.Retired || op.State != "final" || op.Pinned || op.RetainUntil == nil || now.Before(*op.RetainUntil)) {
				return errV2Limited
			}
		}
	}
	st := clone(s.state)
	st.Namespaces = append(st.Namespaces[:i], st.Namespaces[i+1:]...)
	st.Clock = now.UTC()
	return s.publish(st)
}

func (s *v2Store) retireSubjectRecord(id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked || now.Before(s.state.Clock) {
		return errV2Unavailable
	}
	i := -1
	for j, subject := range s.state.Subjects {
		if subject.ID == id {
			i = j
			if !subject.Retired {
				return errV2Invalid
			}
		}
	}
	if i < 0 {
		return errV2NotFound
	}
	for _, ns := range s.state.Namespaces {
		if ns.Subject == id {
			return errV2Limited
		}
	}
	for _, credit := range s.state.ClosingCredits {
		if credit.Subject == id {
			return errV2Limited
		}
	}
	if s.state.Migration != "" {
		var migration v2Migration
		if s.readObject(s.state.Migration, &migration) != nil {
			return errV2Unavailable
		}
		for _, binding := range migration.Bindings {
			if binding.Subject == id {
				return errV2Limited
			}
		}
	}
	st := clone(s.state)
	st.Subjects = append(st.Subjects[:i], st.Subjects[i+1:]...)
	st.Clock = now.UTC()
	return s.publish(st)
}

// A locked finalization may spend reservations released by that same proposed
// state, including its selector publication. Other operations remain reserved.
func (s *v2Store) releasedAllowance(st *v2State) (func(), error) {
	if st == nil || st.ReservedBytes > s.state.ReservedBytes || st.ReservedInodes > s.state.ReservedInodes || !v2ValidState(*st) {
		return nil, errV2Invalid
	}
	previous := s.allowance
	s.allowance = v2Budget{Bytes: max(previous.Bytes, s.state.ReservedBytes-st.ReservedBytes), Inodes: max(previous.Inodes, s.state.ReservedInodes-st.ReservedInodes)}
	return func() { s.allowance = previous }, nil
}

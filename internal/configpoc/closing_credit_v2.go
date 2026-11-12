package configpoc

import (
	"fmt"
	"time"
)

const v2ClosingReserveBytes uint64 = 512 << 20
const v2ClosingReserveInodes uint64 = 8192
const v2MaximumClosingCredits = 8

type v2ClosingOpen struct {
	Operation string `json:"operation"`
	Origin    string `json:"origin"`
	Credit    string `json:"credit"`
}

type v2ClosingCredit struct {
	ID               string `json:"id"`
	Origin           string `json:"origin"`
	Subject          string `json:"subject"`
	Domain           string `json:"domain"`
	Namespace        string `json:"namespace"`
	Child            string `json:"child,omitempty"`
	ChildNamespace   string `json:"child_namespace,omitempty"`
	ClosingNamespace string `json:"closing_namespace,omitempty"`
}

func closingPotentialV2(request v2Request) bool {
	return request.Kind == OpRollback || (request.Kind == OpCommit && request.ConfirmSeconds != nil && *request.ConfirmSeconds > 0)
}

func closingCreditIndexV2(st *v2State, origin string) int {
	for i, credit := range st.ClosingCredits {
		if credit.Origin == origin {
			return i
		}
	}
	return -1
}

func closingRegistryReservedV2(st v2State) uint64 {
	var count uint64
	for _, credit := range st.ClosingCredits {
		if credit.ClosingNamespace == "" {
			count++
		}
	}
	return count
}

func closingEntriesReservedV2(st v2State) uint64 {
	var count uint64
	for _, credit := range st.ClosingCredits {
		if credit.Child == "" {
			count++
		}
	}
	return count
}

// Called by the trusted prepared assembly, under the existing writer lock.
// It changes neither the caller's budget nor the default legacy encoding.
func (s *v2Store) enableClosingCreditsLocked() error {
	if s.blocked {
		return errV2Unavailable
	}
	if s.state.RecoveryReserveVersion == 1 {
		return nil
	}
	if s.state.RecoveryReserveVersion != 0 || s.used.Bytes > s.budget.Bytes || s.budget.Bytes-s.used.Bytes < v2ClosingReserveBytes+2*v2OperationReserveBytes || s.used.Inodes > s.budget.Inodes || s.budget.Inodes-s.used.Inodes < v2ClosingReserveInodes+2*v2OperationReserveInodes {
		return errV2Limited
	}
	for _, ns := range s.state.Namespaces {
		if len(namespaceOpenIDsV2(ns)) != 0 {
			return errV2Uncertain
		}
	}
	if c := s.state.Configuration; c != nil && (c.Pending != nil || c.Intent != nil || c.RecoveryRequired) {
		return errV2Uncertain
	}
	st := clone(s.state)
	err := s.visitOrdinaryIndexV2(st.Index, 2, 0, func(op v2Operation) error {
		if !op.Retired {
			st.OccupiedOrdinary++
		}
		return nil
	})
	if err != nil {
		return err
	}
	st.RecoveryReserveVersion = 1
	return s.publish(st)
}

func validClosingStateV2(st v2State, ordinaryReservations uint64) bool {
	if st.RecoveryReserveVersion == 0 {
		if len(st.ClosingCredits) != 0 || st.ReserveArchiveRoot != "" || st.ClosingIndexRoot != "" || st.OccupiedOrdinary != 0 || st.OccupiedClosing != 0 {
			return false
		}
		for _, ns := range st.Namespaces {
			if ns.ClosingOrigin != "" || len(ns.ClosingOpen) != 0 {
				return false
			}
		}
		return st.ReservedBytes == ordinaryReservations*v2OperationReserveBytes && st.ReservedInodes == ordinaryReservations*v2OperationReserveInodes
	}
	if st.RecoveryReserveVersion != 1 || len(st.ClosingCredits) > v2MaximumClosingCredits || (st.ReserveArchiveRoot != "" && !validHash(st.ReserveArchiveRoot)) || (st.ClosingIndexRoot != "" && !validHash(st.ClosingIndexRoot)) || (st.OccupiedClosing == 0) != (st.ClosingIndexRoot == "") || st.OccupiedOrdinary > st.LiveSlots || st.OccupiedClosing > st.LiveSlots || st.OccupiedOrdinary+st.OccupiedClosing+closingEntriesReservedV2(st) > st.LiveSlots || uint64(len(st.Namespaces))+closingRegistryReservedV2(st) > st.NamespaceSlots {
		return false
	}
	seenIDs, seenOrigins, seenChildren := map[string]bool{}, map[string]bool{}, map[string]bool{}
	credits := map[string]v2ClosingCredit{}
	for _, credit := range st.ClosingCredits {
		if credit.ID == "" || len(credit.ID) > 128 || credit.Origin == "" || len(credit.Origin) > 128 || seenIDs[credit.ID] || seenOrigins[credit.Origin] || credit.Subject == "" || len(credit.Subject) > 128 || (credit.Domain != "firewall" && credit.Domain != "local_services") || credit.Namespace == "" || len(credit.Namespace) > 128 || len(credit.Child) > 128 || len(credit.ChildNamespace) > 128 || len(credit.ClosingNamespace) > 128 || (credit.Child == "") != (credit.ChildNamespace == "") || credit.Child == credit.Origin || (credit.Child != "" && seenChildren[credit.Child]) {
			return false
		}
		seenIDs[credit.ID], seenOrigins[credit.Origin] = true, true
		if credit.Child != "" {
			seenChildren[credit.Child] = true
		}
		credits[credit.ID] = credit
		owner, originNS, fallbackNS, childNS := false, false, credit.ClosingNamespace == "", credit.ChildNamespace == ""
		for _, subject := range st.Subjects {
			if subject.ID == credit.Subject {
				owner = true
			}
		}
		for _, ns := range st.Namespaces {
			if ns.ID == credit.ChildNamespace && ns.Subject == credit.Subject && ns.Domain == credit.Domain {
				childNS = true
			}
			if ns.ID == credit.Namespace && ns.Subject == credit.Subject && ns.Domain == credit.Domain {
				originNS = true
			}
			if ns.ID == credit.ClosingNamespace && ns.Subject == credit.Subject && ns.Domain == credit.Domain && ns.ClosingOrigin == credit.Origin {
				fallbackNS = true
			}
		}
		if !owner || !originNS || !fallbackNS || !childNS {
			return false
		}
	}
	for id := range seenChildren {
		if seenOrigins[id] {
			return false
		}
	}
	open := map[string]bool{}
	for _, ns := range st.Namespaces {
		if ns.ClosingOrigin != "" {
			if len(ns.Open) != 0 {
				return false
			}
			found := false
			for _, credit := range st.ClosingCredits {
				if credit.Origin == ns.ClosingOrigin && credit.ClosingNamespace == ns.ID {
					found = true
				}
			}
			if !found {
				return false
			}
		}
		for _, child := range ns.ClosingOpen {
			credit, ok := credits[child.Credit]
			if !ok || child.Operation == "" || open[child.Operation] || child.Operation != credit.Child || child.Origin != credit.Origin || ns.ID != credit.ChildNamespace || ns.Subject != credit.Subject || ns.Domain != credit.Domain {
				return false
			}
			for _, id := range ns.Open {
				if id == child.Operation {
					return false
				}
			}
			open[child.Operation] = true
		}
	}
	if len(open) > v2MaximumClosingCredits {
		return false
	}
	return st.ReservedBytes == ordinaryReservations*v2OperationReserveBytes+uint64(len(st.ClosingCredits))*v2ClosingReserveBytes && st.ReservedInodes == ordinaryReservations*v2OperationReserveInodes+uint64(len(st.ClosingCredits))*v2ClosingReserveInodes
}

func (s *v2Store) ordinarySlotHashV2(slot uint64) (string, error) {
	root := s.state.Index
	for level := 2; level >= 0; level-- {
		if root == "" {
			return "", errV2NotFound
		}
		var page v2Page
		if s.readObject(root, &page) != nil || !v2ValidPage(page, level) {
			return "", errV2Unavailable
		}
		root = page.Refs[(slot>>uint(level*6))&63]
	}
	if root == "" {
		return "", errV2NotFound
	}
	return root, nil
}

func (s *v2Store) closingOriginLocked(subject, domain, origin, target string, now time.Time) (int, v2Operation, error) {
	i := closingCreditIndexV2(&s.state, origin)
	if i < 0 {
		return -1, v2Operation{}, errV2Invalid
	}
	credit := s.state.ClosingCredits[i]
	if credit.Subject != subject || credit.Domain != domain || credit.Child != "" {
		return -1, v2Operation{}, errV2Invalid
	}
	op, err := s.lookupRetained(subject, origin)
	if err != nil {
		return -1, v2Operation{}, err
	}
	if op.Domain != domain || op.State != "final" || !op.Pinned || op.Retired || op.Outcome == nil || op.Outcome.Code != "applied_pending_confirmation" || op.Outcome.ConfirmationLease == "" || op.Outcome.ConfirmationDeadline == nil || !now.Before(*op.Outcome.ConfirmationDeadline) || op.Outcome.RunningRevision != target {
		return -1, v2Operation{}, ErrConflict
	}
	if c := s.state.Configuration; c != nil {
		p := c.Pending
		if p == nil || p.Owner != subject || p.Domain != domain || p.OriginCommit != origin || p.Target != target || p.Lease != op.Outcome.ConfirmationLease || !p.Deadline.Equal(*op.Outcome.ConfirmationDeadline) || c.Intent != nil || c.RecoveryRequired {
			return -1, v2Operation{}, ErrConflict
		}
	}
	return i, op, nil
}

func (s *v2Store) closingNamespaceLocked(subject, domain string, now time.Time, lifetime time.Duration) (v2Namespace, error) {
	for _, credit := range s.state.ClosingCredits {
		if credit.Subject != subject || credit.Domain != domain || credit.Child != "" || credit.ClosingNamespace != "" {
			continue
		}
		origin, err := s.lookupRetained(subject, credit.Origin)
		if err != nil || origin.Outcome == nil {
			continue
		}
		if _, _, err = s.closingOriginLocked(subject, domain, credit.Origin, origin.Outcome.RunningRevision, now); err != nil {
			continue
		}
		if s.state.NamespaceSequence == ^uint64(0) {
			return v2Namespace{}, errV2Limited
		}
		id, err := v2ID("ns", s.state.NamespaceSequence+1)
		if err != nil {
			return v2Namespace{}, err
		}
		until := now.UTC().Add(lifetime)
		if until.After(*origin.Outcome.ConfirmationDeadline) {
			until = *origin.Outcome.ConfirmationDeadline
		}
		ns := v2Namespace{ID: id, Subject: subject, Domain: domain, AdmitUntil: until, Open: []string{}, ClosingOrigin: credit.Origin}
		st := clone(s.state)
		st.NamespaceSequence++
		st.Clock = now.UTC()
		st.Namespaces = append(st.Namespaces, ns)
		st.ClosingCredits[closingCreditIndexV2(&st, credit.Origin)].ClosingNamespace = id
		previous := s.allowance
		s.allowance = v2Budget{Bytes: v2ClosingReserveBytes, Inodes: v2ClosingReserveInodes}
		err = s.publish(st)
		s.allowance = previous
		return ns, err
	}
	return v2Namespace{}, errV2Limited
}

func (s *v2Store) closingOperationAllowanceLocked(op v2Operation) (func(), error) {
	previous := s.allowance
	if op.ClosingCredit != "" {
		found := false
		for _, credit := range s.state.ClosingCredits {
			if credit.ID == op.ClosingCredit && credit.Child == op.ID && credit.Subject == op.Subject && credit.Domain == op.Domain && credit.ChildNamespace == op.Namespace {
				found = true
			}
		}
		if !found {
			return nil, errV2Unavailable
		}
		s.allowance = v2Budget{Bytes: v2ClosingReserveBytes, Inodes: v2ClosingReserveInodes}
	}
	return func() { s.allowance = previous }, nil
}

func (s *v2Store) closingBatchAllowanceLocked(children []v2ClosingOpen, expireAt *time.Time) (func(), error) {
	previous := s.allowance
	for _, child := range children {
		var credit *v2ClosingCredit
		for i := range s.state.ClosingCredits {
			if s.state.ClosingCredits[i].ID == child.Credit {
				credit = &s.state.ClosingCredits[i]
			}
		}
		if credit == nil {
			s.allowance = previous
			return nil, errV2Unavailable
		}
		op, err := s.lookupRetained(credit.Subject, child.Operation)
		if err != nil {
			s.allowance = previous
			return nil, err
		}
		if op.State != "accepted" || (expireAt != nil && expireAt.Before(op.ExecuteBefore)) {
			continue
		}
		if _, err = s.closingOperationAllowanceLocked(op); err != nil {
			s.allowance = previous
			return nil, err
		}
	}
	return func() { s.allowance = previous }, nil
}

// The caller must first prove canonical archival and exact physical retirement.
// This only releases ledger ownership after origin/child are terminal and unpinned.
func (s *v2Store) releaseClosingCreditLocked(origin, id, child string, now time.Time) error {
	i := closingCreditIndexV2(&s.state, origin)
	if s.blocked || i < 0 || now.Before(s.state.Clock) {
		return errV2Invalid
	}
	credit := s.state.ClosingCredits[i]
	if credit.ID != id || credit.Child != child {
		return errV2Invalid
	}
	for _, work := range []string{origin, child} {
		if work == "" {
			continue
		}
		op, err := s.lookupRetained(credit.Subject, work)
		if err != nil || op.State != "final" || op.Pinned || op.Outcome == nil {
			return errV2Uncertain
		}
	}
	if c := s.state.Configuration; c != nil {
		if c.Intent != nil || c.RecoveryRequired || (c.Pending != nil && c.Pending.OriginCommit == origin) {
			return errV2Uncertain
		}
	}
	st := clone(s.state)
	st.ClosingCredits = append(st.ClosingCredits[:i], st.ClosingCredits[i+1:]...)
	st.ReservedBytes -= v2ClosingReserveBytes
	st.ReservedInodes -= v2ClosingReserveInodes
	for j := range st.Namespaces {
		if st.Namespaces[j].ClosingOrigin == origin {
			if len(st.Namespaces[j].ClosingOpen) != 0 {
				return errV2Uncertain
			}
			st.Namespaces[j].ClosingOrigin = ""
			st.Namespaces[j].Closed = true
		}
	}
	st.Clock = now.UTC()
	previous := s.allowance
	s.allowance = v2Budget{Bytes: v2ClosingReserveBytes, Inodes: v2ClosingReserveInodes}
	defer func() { s.allowance = previous }()
	return s.publish(st)
}

func closingSequenceKeyV2(sequence uint64) string { return fmt.Sprintf("%016x%048x", sequence, 0) }

func (s *v2Store) visitOrdinaryIndexV2(root string, level int, position uint64, visit func(v2Operation) error) error {
	if root == "" {
		return nil
	}
	var page v2Page
	if level < 0 || level > 2 || s.readObject(root, &page) != nil || !v2ValidPage(page, level) {
		return errV2Unavailable
	}
	for i, hash := range page.Refs {
		if hash == "" {
			continue
		}
		nextPosition := position | uint64(i)<<uint(level*6)
		if level > 0 {
			if err := s.visitOrdinaryIndexV2(hash, level-1, nextPosition, visit); err != nil {
				return err
			}
			continue
		}
		var op v2Operation
		if nextPosition >= s.state.LiveSlots || s.readObject(hash, &op) != nil || !s.validOperation(op) || op.ClosingCredit != "" || (op.Sequence-1)%s.state.LiveSlots != nextPosition {
			return errV2Unavailable
		}
		if err := visit(op); err != nil {
			return err
		}
	}
	return nil
}

func closingBudgetFitsV2(used, reserved, needed, budget uint64) bool {
	return used <= budget && reserved <= budget-used && needed <= budget-used-reserved
}

func namespaceOpenIDsV2(ns v2Namespace) []string {
	ids := append([]string{}, ns.Open...)
	for _, child := range ns.ClosingOpen {
		ids = append(ids, child.Operation)
	}
	return ids
}

func (s *v2Store) admitClosingLocked(subject, namespace string, expected uint64, request v2Request, now time.Time) (v2Operation, error) {
	i := s.namespaceIndex(subject, namespace)
	if i < 0 || s.state.RecoveryReserveVersion != 1 || request.Kind != OpConfirm || expected != s.state.Generation || s.state.HighWater == ^uint64(0) {
		return v2Operation{}, ErrConflict
	}
	ns := s.state.Namespaces[i]
	creditIndex, origin, err := s.closingOriginLocked(subject, ns.Domain, request.Origin, request.Target, now)
	if err != nil {
		return v2Operation{}, err
	}
	if ns.ClosingOrigin != "" && ns.ClosingOrigin != origin.ID {
		return v2Operation{}, errV2Invalid
	}
	credit := s.state.ClosingCredits[creditIndex]
	id, err := v2ID("op", s.state.HighWater+1)
	if err != nil {
		return v2Operation{}, err
	}
	deadline := now.UTC().Add(900 * time.Second)
	if deadline.After(ns.AdmitUntil) {
		deadline = ns.AdmitUntil
	}
	if deadline.After(*origin.Outcome.ConfirmationDeadline) {
		deadline = *origin.Outcome.ConfirmationDeadline
	}
	op := v2Operation{ID: id, Namespace: namespace, Subject: subject, Lineage: s.state.Lineage, Domain: ns.Domain, Sequence: s.state.HighWater + 1, Expected: expected, Request: clone(request), State: "accepted", Accepted: now.UTC(), ExecuteBefore: deadline, ClosingCredit: credit.ID}
	op.Fingerprint = v2OperationFingerprint(op)
	st := clone(s.state)
	st.HighWater++
	st.OccupiedClosing++
	st.Clock = now.UTC()
	st.ClosingCredits[creditIndex].Child = id
	st.ClosingCredits[creditIndex].ChildNamespace = namespace
	st.Namespaces[i].ClosingOpen = append(st.Namespaces[i].ClosingOpen, v2ClosingOpen{Operation: id, Origin: origin.ID, Credit: credit.ID})
	if err = s.reserveAdmissionV2(&st, &op); err != nil {
		return v2Operation{}, err
	}
	previous := s.allowance
	s.allowance = v2Budget{Bytes: v2ClosingReserveBytes, Inodes: v2ClosingReserveInodes}
	defer func() { s.allowance = previous }()
	if err = s.putOperation(&st, op); err != nil {
		s.blocked = true
		return v2Operation{}, err
	}
	if err = s.publish(st); err != nil {
		return v2Operation{}, err
	}
	return op, nil
}

package configpoc

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func v2ID(kind string, sequence uint64) (string, error) {
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", errV2Unavailable
	}
	return fmt.Sprintf("v2.%s.%d.%s", kind, sequence, base64.RawURLEncoding.EncodeToString(random[:])), nil
}

func v2ValidPage(page v2Page, level int) bool {
	if page.Format != v2Format || page.Level != level {
		return false
	}
	for _, hash := range page.Refs {
		if hash != "" && !v2HashPattern.MatchString(hash) {
			return false
		}
	}
	return true
}

// The fixed three-level radix index holds hashes only. A lookup reads at most
// three 64-entry pages plus one operation; there is no lifetime-sized cache.
func (s *v2Store) indexGet(root string, sequence uint64) (string, error) {
	if sequence == 0 || sequence > s.state.HighWater {
		return "", errV2NotFound
	}
	position := (sequence - 1) % s.state.LiveSlots
	for level := 2; level >= 0; level-- {
		if root == "" {
			return "", errV2NotFound
		}
		var page v2Page
		if s.readObject(root, &page) != nil || !v2ValidPage(page, level) {
			return "", errV2Unavailable
		}
		root = page.Refs[(position>>uint(level*6))&63]
	}
	if root == "" {
		return "", errV2NotFound
	}
	return root, nil
}
func (s *v2Store) indexPut(root string, level int, sequence uint64, operation string) (string, error) {
	if sequence == 0 || level < 0 || level > 2 || !v2HashPattern.MatchString(operation) {
		return "", errV2Invalid
	}
	page := v2Page{Format: v2Format, Level: level}
	if root != "" {
		if s.readObject(root, &page) != nil || !v2ValidPage(page, level) {
			return "", errV2Unavailable
		}
	}
	position := (((sequence - 1) % s.state.LiveSlots) >> uint(level*6)) & 63
	next := operation
	if level > 0 {
		var err error
		next, err = s.indexPut(page.Refs[position], level-1, sequence, operation)
		if err != nil {
			return "", err
		}
	}
	page.Refs[position] = next
	return s.objectClass(page, true)
}

func (s *v2Store) subject(id string) bool {
	for _, sub := range s.state.Subjects {
		if sub.ID == id {
			return !sub.Retired
		}
	}
	return false
}
func (s *v2Store) namespaceIndex(subject, id string) int {
	for i, ns := range s.state.Namespaces {
		if ns.ID == id && ns.Subject == subject {
			return i
		}
	}
	return -1
}
func (s *v2Store) namespace(subject, domain string, now time.Time, lifetime time.Duration) (v2Namespace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.namespaceLocked(subject, domain, now, lifetime)
}

func (s *v2Store) namespaceLocked(subject, domain string, now time.Time, lifetime time.Duration) (v2Namespace, error) {
	if s.blocked {
		return v2Namespace{}, errV2Unavailable
	}
	if !s.subject(subject) || !configurationDomainV2(domain, hasFeatureV2(s.state, v2RoutedFeature)) || lifetime <= 0 || lifetime > 24*time.Hour || now.Before(s.state.Clock) {
		return v2Namespace{}, errV2Invalid
	}
	for _, ns := range s.state.Namespaces {
		if ns.Subject == subject && ns.Domain == domain && ns.ClosingOrigin == "" && !ns.Closed && now.Before(ns.AdmitUntil) {
			return clone(ns), nil
		}
	}
	if s.state.RecoveryReserveVersion == 1 {
		for _, ns := range s.state.Namespaces {
			if ns.Subject == subject && ns.Domain == domain && ns.ClosingOrigin != "" && !ns.Closed && now.Before(ns.AdmitUntil) {
				return clone(ns), nil
			}
		}
		if ns, err := s.closingNamespaceLocked(subject, domain, now, lifetime); err == nil {
			return ns, nil
		} else if err != errV2Limited {
			return v2Namespace{}, err
		}
	}
	if uint64(len(s.state.Namespaces))+closingRegistryReservedV2(s.state) >= s.state.NamespaceSlots || s.state.NamespaceSequence == ^uint64(0) {
		return v2Namespace{}, errV2Limited
	}
	id, err := v2ID("ns", s.state.NamespaceSequence+1)
	if err != nil {
		return v2Namespace{}, err
	}
	ns := v2Namespace{ID: id, Subject: subject, Domain: domain, AdmitUntil: now.UTC().Add(lifetime), Open: []string{}}
	st := clone(s.state)
	st.NamespaceSequence++
	st.Clock = now.UTC()
	st.Namespaces = append(st.Namespaces, ns)
	if st.RecoveryReserveVersion == 1 && !reserveMetadataStateFitsV2(st) {
		return v2Namespace{}, errV2Limited
	}
	if err = s.publish(st); err != nil {
		return v2Namespace{}, err
	}
	return ns, nil
}

func (s *v2Store) admit(subject, namespace string, expected uint64, request v2Request, now time.Time) (v2Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.admitLocked(subject, namespace, expected, request, now)
}

func (s *v2Store) admitLocked(subject, namespace string, expected uint64, request v2Request, now time.Time) (v2Operation, error) {
	if s.blocked {
		return v2Operation{}, errV2Unavailable
	}
	i := s.namespaceIndex(subject, namespace)
	if i < 0 || !s.subject(subject) {
		return v2Operation{}, errV2NotFound
	}
	ns := s.state.Namespaces[i]
	if hasFeatureV2(s.state, v2RoutedFeature) && s.state.Configuration != nil && s.state.Configuration.Firewall.Running.Config.SchemaVersion == 6 && ns.Domain != "routed" {
		return v2Operation{}, ErrDenied
	}
	if ns.Closed {
		return v2Operation{}, errV2Closed
	}
	if now.Before(s.state.Clock) {
		return v2Operation{}, errV2Unavailable
	}
	if !now.Before(ns.AdmitUntil) {
		return v2Operation{}, errV2Expired
	}
	if expected == 0 || !v2RequestValid(ns.Domain, request) {
		return v2Operation{}, errV2Invalid
	}
	if request.Config != nil {
		canonical, e := canonicalDomainRevisionV2(*request.Config, ns.Domain == "routed")
		if e != nil {
			return v2Operation{}, errV2Invalid
		}
		request.Config = &canonical.Config
	}
	if request.LocalServicesConfig != nil {
		canonical, e := Canonical(*request.LocalServicesConfig)
		if e != nil {
			return v2Operation{}, errV2Invalid
		}
		request.LocalServicesConfig = &canonical.Config
	}
	data, _, err := v2Canonical(request)
	if err != nil || len(data) > 8192 {
		return v2Operation{}, errV2Invalid
	}
	if err := s.reserveBeforeAdmissionV2(); err != nil {
		return v2Operation{}, err
	}
	if s.state.RecoveryReserveVersion == 1 && request.Kind == OpConfirm {
		return s.admitClosingLocked(subject, namespace, expected, request, now)
	}
	if ns.ClosingOrigin != "" {
		return v2Operation{}, errV2Invalid
	}
	closingBytes, closingInodes := uint64(0), uint64(0)
	if s.state.RecoveryReserveVersion == 1 {
		entries := s.state.OccupiedOrdinary + s.state.OccupiedClosing + closingEntriesReservedV2(s.state) + 1
		if closingPotentialV2(request) {
			if len(s.state.ClosingCredits) >= v2MaximumClosingCredits || uint64(len(s.state.Namespaces))+closingRegistryReservedV2(s.state) >= s.state.NamespaceSlots {
				return v2Operation{}, errV2Limited
			}
			closingBytes, closingInodes = v2ClosingReserveBytes, v2ClosingReserveInodes
			entries++
		}
		if entries > s.state.LiveSlots {
			return v2Operation{}, errV2Limited
		}
	}
	// Worst-case lifecycle plus a separate double-selection margin. These are
	// accounting checks, not a filesystem quota or a physical reservation.
	if len(ns.Open) >= v2MaximumOpen || s.state.HighWater == ^uint64(0) || !closingBudgetFitsV2(s.used.Bytes, s.state.ReservedBytes, 2*v2OperationReserveBytes+closingBytes, s.budget.Bytes) || !closingBudgetFitsV2(s.used.Inodes, s.state.ReservedInodes, 2*v2OperationReserveInodes+closingInodes, s.budget.Inodes) {
		return v2Operation{}, errV2Limited
	}
	if err := s.physicalCapacity(2*v2OperationReserveBytes+closingBytes, 2*v2OperationReserveInodes+closingInodes); err != nil {
		return v2Operation{}, err
	}
	if s.state.RecoveryReserveVersion == 1 {
		hash, e := s.ordinarySlotHashV2(s.state.HighWater % s.state.LiveSlots)
		if e != nil && e != errV2NotFound {
			return v2Operation{}, e
		}
		if e == nil {
			var old v2Operation
			if s.readObject(hash, &old) != nil || !s.validOperation(old) {
				return v2Operation{}, errV2Unavailable
			}
			if !old.Retired || old.State != "final" || old.Pinned || old.RetainUntil == nil || now.Before(*old.RetainUntil) {
				return v2Operation{}, errV2Limited
			}
		}
	} else if s.state.HighWater >= s.state.LiveSlots {
		hash, e := s.indexGet(s.state.Index, s.state.HighWater+1-s.state.LiveSlots)
		var old v2Operation
		if e != nil || s.readObject(hash, &old) != nil || !s.validOperation(old) {
			return v2Operation{}, errV2Unavailable
		}
		if !old.Retired || old.State != "final" || old.Pinned || old.RetainUntil == nil || now.Before(*old.RetainUntil) {
			return v2Operation{}, errV2Limited
		}
	}
	id, err := v2ID("op", s.state.HighWater+1)
	if err != nil {
		return v2Operation{}, err
	}
	deadline := now.UTC().Add(900 * time.Second)
	if deadline.After(ns.AdmitUntil) {
		deadline = ns.AdmitUntil
	}
	op := v2Operation{ID: id, Namespace: namespace, Subject: subject, Lineage: s.state.Lineage, Domain: ns.Domain, Sequence: s.state.HighWater + 1, Expected: expected, Request: clone(request), State: "accepted", Accepted: now.UTC(), ExecuteBefore: deadline}
	op.Fingerprint = v2OperationFingerprint(op)
	st := clone(s.state)
	st.HighWater++
	st.Clock = now.UTC()
	st.Namespaces[i].Open = append(st.Namespaces[i].Open, id)
	st.ReservedBytes += v2OperationReserveBytes
	st.ReservedInodes += v2OperationReserveInodes
	if st.RecoveryReserveVersion == 1 {
		st.OccupiedOrdinary++
		if closingBytes != 0 {
			creditID, e := v2ID("closing", op.Sequence)
			if e != nil {
				return v2Operation{}, e
			}
			st.ClosingCredits = append(st.ClosingCredits, v2ClosingCredit{ID: creditID, Origin: op.ID, Subject: subject, Domain: ns.Domain, Namespace: ns.ID})
			st.ReservedBytes += closingBytes
			st.ReservedInodes += closingInodes
		}
	}
	if err = s.reserveAdmissionV2(&st, &op); err != nil {
		return v2Operation{}, err
	}
	if err = s.putOperation(&st, op); err != nil {
		s.blocked = true
		return v2Operation{}, err
	}
	if err = s.publish(st); err != nil {
		return v2Operation{}, err
	}
	return op, nil
}

func (s *v2Store) putOperation(st *v2State, op v2Operation) error {
	hash, err := s.object(op)
	if err != nil {
		return err
	}
	if op.ClosingCredit != "" {
		if st.RecoveryReserveVersion != 1 {
			return errV2Invalid
		}
		if op.Retired {
			hash = ""
		}
		st.ClosingIndexRoot, err = s.closingIndexPut(st.ClosingIndexRoot, 0, op.Sequence, hash)
		return err
	}
	st.Index, err = s.indexPut(st.Index, 2, op.Sequence, hash)
	return err
}

func (s *v2Store) lookup(subject, id string) (v2Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked {
		return v2Operation{}, errV2Unavailable
	}
	return s.lookupLocked(subject, id)
}
func (s *v2Store) lookupLocked(subject, id string) (v2Operation, error) {
	if !s.subject(subject) {
		return v2Operation{}, errV2NotFound
	}
	return s.lookupRetained(subject, id)
}

func (s *v2Store) lookupRetained(subject, id string) (v2Operation, error) {
	if len(id) > 128 {
		return v2Operation{}, errV2NotFound
	}
	parts := strings.Split(id, ".")
	if len(parts) != 4 || parts[0] != "v2" || parts[1] != "op" {
		return v2Operation{}, errV2NotFound
	}
	seq, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || strconv.FormatUint(seq, 10) != parts[2] {
		return v2Operation{}, errV2NotFound
	}
	hash, err := s.catalogueHashV2(seq)
	if err != nil {
		return v2Operation{}, err
	}
	var op v2Operation
	if s.readObject(hash, &op) != nil || !s.validOperation(op) {
		return v2Operation{}, errV2Unavailable
	}
	if op.ID != id || op.Sequence != seq || op.Subject != subject || op.Lineage != s.state.Lineage {
		return v2Operation{}, errV2NotFound
	}
	if op.Retired {
		return v2Operation{}, errV2Expired
	}
	return op, nil
}

func (s *v2Store) validOperation(op v2Operation) bool {
	if op.Sequence == 0 || op.Sequence > s.state.HighWater || op.Lineage != s.state.Lineage || op.Expected == 0 || !v2RequestValid(op.Domain, op.Request) || op.Fingerprint != v2OperationFingerprint(op) || !op.ExecuteBefore.After(op.Accepted) || op.ExecuteBefore.Sub(op.Accepted) > 900*time.Second {
		return false
	}
	i := s.namespaceIndex(op.Subject, op.Namespace)
	if i < 0 {
		return op.Retired && op.State == "final" && !op.Pinned && op.Completed != nil && op.RetainUntil != nil && !op.RetainUntil.Before(op.Completed.Add(30*24*time.Hour)) && op.Outcome != nil && v2HashPattern.MatchString(op.Outcome.AuditHash)
	}
	if s.state.Namespaces[i].Domain != op.Domain {
		return false
	}
	open := false
	for _, id := range s.state.Namespaces[i].Open {
		if id == op.ID {
			open = true
		}
	}
	for _, child := range s.state.Namespaces[i].ClosingOpen {
		if child.Operation == op.ID {
			if open || op.ClosingCredit == "" || op.ClosingCredit != child.Credit || op.Request.Kind != OpConfirm || op.Request.Origin != child.Origin {
				return false
			}
			open = true
		}
	}
	if op.ClosingCredit != "" && s.state.RecoveryReserveVersion != 1 {
		return false
	}
	if open != (op.State != "final" || op.Pinned) {
		return false
	}
	switch op.State {
	case "accepted", "pending", "uncertain":
		return op.Completed == nil && op.RetainUntil == nil && op.Outcome == nil
	case "final":
		return op.Completed != nil && op.RetainUntil != nil && !op.RetainUntil.Before(op.Completed.Add(30*24*time.Hour)) && op.Outcome != nil && v2HashPattern.MatchString(op.Outcome.AuditHash)
	}
	return false
}

// begin is the durable authorization boundary for a future coordinator. It
// invokes no engine. Pending/final retries are observations, never effects.
func (s *v2Store) begin(subject, id string, now time.Time) (v2Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Configuration != nil {
		return v2Operation{}, errV2Invalid
	}
	if s.blocked {
		return v2Operation{}, errV2Unavailable
	}
	op, err := s.lookupLocked(subject, id)
	if err != nil {
		return v2Operation{}, err
	}
	if op.State != "accepted" {
		return op, nil
	}
	for _, namespace := range s.state.Namespaces {
		for _, otherID := range namespaceOpenIDsV2(namespace) {
			if otherID == id {
				continue
			}
			other, e := s.lookupRetained(namespace.Subject, otherID)
			if e != nil {
				return v2Operation{}, e
			}
			if other.State == "pending" || other.State == "uncertain" {
				return v2Operation{}, errV2Uncertain
			}
		}
	}
	ns := s.state.Namespaces[s.namespaceIndex(subject, op.Namespace)]
	if ns.Closed {
		return v2Operation{}, errV2Closed
	}
	if now.Before(s.state.Clock) {
		return v2Operation{}, errV2Unavailable
	}
	if !now.Before(op.ExecuteBefore) {
		return v2Operation{}, errV2Expired
	}
	if op.Expected != s.state.Generation {
		return v2Operation{}, ErrConflict
	}
	op.State = "pending"
	op.Pinned = true
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = v2Budget{} }()
	restore, err := s.closingOperationAllowanceLocked(op)
	if err != nil {
		return v2Operation{}, err
	}
	defer restore()
	st := clone(s.state)
	st.Clock = now.UTC()
	if err = s.putOperation(&st, op); err != nil {
		s.blocked = true
		return v2Operation{}, err
	}
	if err = s.publish(st); err != nil {
		return v2Operation{}, err
	}
	return op, nil
}

// finish persists a caller-verified result and its protected audit boundary in
// the same selection. A–C does not claim that the supplied effects were applied.
func (s *v2Store) finish(subject, id string, outcome v2Outcome, audit []byte, now time.Time, pin bool) (v2Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Configuration != nil {
		return v2Operation{}, errV2Invalid
	}
	if s.blocked {
		return v2Operation{}, errV2Unavailable
	}
	op, err := s.lookupLocked(subject, id)
	if err != nil {
		return v2Operation{}, err
	}
	if op.State == "final" {
		return op, nil
	}
	if op.State != "pending" || now.Before(s.state.Clock) || len(audit) == 0 || len(audit) > 8192 || outcome.AuditHash != "" || outcome.Generation < s.state.Generation || outcome.Generation > s.state.Generation+1 {
		return v2Operation{}, errV2Invalid
	}
	switch outcome.Code {
	case "applied", "applied_pending_confirmation", "rejected", "failed_rolled_back":
	default:
		return v2Operation{}, errV2Invalid
	}
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = v2Budget{} }()
	restore, err := s.closingOperationAllowanceLocked(op)
	if err != nil {
		return v2Operation{}, err
	}
	defer restore()
	auditHash, err := s.object(struct {
		Format    string `json:"format"`
		Operation string `json:"operation"`
		Data      []byte `json:"data"`
	}{v2Format, id, audit})
	if err != nil {
		s.blocked = true
		return v2Operation{}, err
	}
	outcome.AuditHash = auditHash
	completed := now.UTC()
	until := completed.Add(30 * 24 * time.Hour)
	op.State = "final"
	op.Outcome = &outcome
	op.Completed = &completed
	op.RetainUntil = &until
	op.Pinned = pin
	st := clone(s.state)
	st.Generation = outcome.Generation
	st.Clock = completed
	if !pin {
		v2Release(&st, op)
	}
	if err = s.putOperation(&st, op); err != nil {
		s.blocked = true
		return v2Operation{}, err
	}
	if err = s.publish(st); err != nil {
		return v2Operation{}, err
	}
	return op, nil
}

func v2Release(st *v2State, op v2Operation) {
	if op.ClosingCredit != "" {
		for i := range st.Namespaces {
			for j, child := range st.Namespaces[i].ClosingOpen {
				if child.Operation == op.ID && child.Credit == op.ClosingCredit {
					st.Namespaces[i].ClosingOpen = append(st.Namespaces[i].ClosingOpen[:j], st.Namespaces[i].ClosingOpen[j+1:]...)
					return
				}
			}
		}
		return
	}
	for i := range st.Namespaces {
		if st.Namespaces[i].ID == op.Namespace {
			for j, id := range st.Namespaces[i].Open {
				if id == op.ID {
					st.Namespaces[i].Open = append(st.Namespaces[i].Open[:j], st.Namespaces[i].Open[j+1:]...)
					if holdReserveCanonicalV2(st, op) {
						return
					}
					st.ReservedBytes -= v2OperationReserveBytes
					st.ReservedInodes -= v2OperationReserveInodes
					return
				}
			}
		}
	}
}

func (s *v2Store) list(subject, namespace string, after uint64, limit int) ([]v2Operation, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked(subject, namespace, after, limit)
}

func (s *v2Store) listLocked(subject, namespace string, after uint64, limit int) ([]v2Operation, uint64, error) {
	if s.blocked {
		return nil, 0, errV2Unavailable
	}
	if limit < 1 || limit > 100 || s.namespaceIndex(subject, namespace) < 0 || !s.subject(subject) {
		return nil, 0, errV2Invalid
	}
	result := []v2Operation{}
	// Bound work as well as output. Cursor is a server internal sequence, not
	// an authorization assertion; every resulting record is checked.
	for count := 0; after < s.state.HighWater && count < 1000; count++ {
		after++
		hash, err := s.catalogueHashV2(after)
		if s.state.RecoveryReserveVersion == 1 && err == errV2NotFound {
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		var op v2Operation
		if s.readObject(hash, &op) != nil || !s.validOperation(op) {
			return nil, 0, errV2Unavailable
		}
		if op.Sequence == after && op.Subject == subject && op.Namespace == namespace && !op.Retired {
			result = append(result, op)
			if len(result) == limit {
				break
			}
		}
	}
	return result, after, nil
}

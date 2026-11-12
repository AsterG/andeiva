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
	return s.object(page)
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
	if !s.subject(subject) || (domain != "firewall" && domain != "local_services") || lifetime <= 0 || lifetime > 24*time.Hour || now.Before(s.state.Clock) {
		return v2Namespace{}, errV2Invalid
	}
	for _, ns := range s.state.Namespaces {
		if ns.Subject == subject && ns.Domain == domain && !ns.Closed && now.Before(ns.AdmitUntil) {
			return clone(ns), nil
		}
	}
	if uint64(len(s.state.Namespaces)) >= s.state.NamespaceSlots || s.state.NamespaceSequence == ^uint64(0) {
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
		canonical, e := Canonical(*request.Config)
		if e != nil {
			return v2Operation{}, errV2Invalid
		}
		request.Config = &canonical.Config
	}
	data, _, err := v2Canonical(request)
	if err != nil || len(data) > 8192 {
		return v2Operation{}, errV2Invalid
	}
	// Worst-case lifecycle plus a separate double-selection margin. These are
	// accounting checks, not a filesystem quota or a physical reservation.
	if len(ns.Open) >= v2MaximumOpen || s.state.HighWater == ^uint64(0) || s.used.Bytes+s.state.ReservedBytes+2*v2OperationReserveBytes > s.budget.Bytes || s.used.Inodes+s.state.ReservedInodes+2*v2OperationReserveInodes > s.budget.Inodes {
		return v2Operation{}, errV2Limited
	}
	if err := s.physicalCapacity(2*v2OperationReserveBytes, 2*v2OperationReserveInodes); err != nil {
		return v2Operation{}, err
	}
	if s.state.HighWater >= s.state.LiveSlots {
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
	hash, err := s.indexGet(s.state.Index, seq)
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
		for _, otherID := range namespace.Open {
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
	for i := range st.Namespaces {
		if st.Namespaces[i].ID == op.Namespace {
			for j, id := range st.Namespaces[i].Open {
				if id == op.ID {
					st.Namespaces[i].Open = append(st.Namespaces[i].Open[:j], st.Namespaces[i].Open[j+1:]...)
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
		hash, err := s.indexGet(s.state.Index, after)
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

package configpoc

import (
	"errors"
	"reflect"
	"sort"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

// Maintenance is serialized with admission and application under the store
// writer lease. A terminal bundle cannot be reused until both actual selected
// anchors preserve its exact bytes and every physical CAS has completed.
func (m *v2ReserveManager) maintain(s *v2Store) error {
	return m.maintainWork(s, "")
}

func (m *v2ReserveManager) maintainWork(s *v2Store, preferred string) error {
	if m == nil || s == nil || s.blocked {
		return ErrRecovery
	}
	// A live lease owns the only application lane. Unrelated expired work
	// keeps its own canonical/physical reserves; it cannot starve Confirm.
	if cfg := s.state.Configuration; cfg != nil && (cfg.Pending != nil || cfg.Intent != nil || cfg.RecoveryRequired) {
		return nil
	}
	for {
		var work *v2ActiveReserve
		if b := s.state.RoutedBootBoundary; b != nil && b.CompletedBoot != "" && b.Resolution != "" && b.OldBoot != nil {
			record, err := (&v2Coordinator{store: s}).recoveryLookupLocked(b.OldBoot.ID)
			if err != nil || record.SupersededBy != b.CompletedBoot {
				return ErrRecovery
			}
			work = &v2ActiveReserve{Work: record.ID, Bundle: record.Reserve, CanonicalHeld: true}
		}
		for _, active := range s.state.ActiveReserves {
			if active.Work == preferred && active.Bundle.Scope.Origin != "" {
				preferred = active.Bundle.Scope.Origin
				break
			}
		}
		for _, active := range s.state.ActiveReserves {
			if work == nil && active.CanonicalHeld && active.Work == preferred {
				value := active
				work = &value
				break
			}
		}
		if work == nil {
			for _, active := range s.state.ActiveReserves {
				if active.CanonicalHeld && active.Bundle.ClosingEscrow != nil {
					value := active
					work = &value
					break
				}
			}
		}
		for _, active := range s.state.ActiveReserves {
			if work == nil && active.CanonicalHeld {
				value := active
				work = &value
				break
			}
		}
		if work == nil && s.state.SystemBundle != nil && s.state.SystemBundle.CanonicalHeld {
			work = clone(s.state.SystemBundle)
		}
		if d := s.state.RoutedDHCP; work == nil && routedDHCPTerminalV3(d) {
			work = &v2ActiveReserve{Work: reserveWorkV2(d.Bundle), Bundle: clone(d.Bundle), CanonicalHeld: true}
		}
		if work == nil {
			return nil
		}
		if err := m.archiveTerminal(s, *work); err != nil {
			return err
		}
		preferred = ""
	}
}

func sortReserveClaimsV2(claims []recoveryreserve.SlotClaimV2) {
	sort.Slice(claims, func(i, j int) bool {
		a, _ := reserveClaimKeyV2(claims[i])
		b, _ := reserveClaimKeyV2(claims[j])
		return a < b
	})
}

func (m *v2ReserveManager) archiveTerminal(s *v2Store, active v2ActiveReserve) error {
	previousAllowance := s.allowance
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = previousAllowance }()
	if active.Bundle.ClosingEscrow != nil {
		s.allowance = v2Budget{Bytes: v2ClosingReserveBytes, Inodes: v2ClosingReserveInodes}
	}
	first := v2ReserveArchiveEntry{Claim: active.Bundle.Claims.Admission}
	archive, known, err := s.reserveArchiveBundleLookupV2(s.state.ReserveArchiveRoot, first, "claim")
	if err != nil {
		return err
	}
	if !known {
		archive, err = m.buildTerminalArchive(s, active)
		if err != nil {
			return err
		}
		hash, err := s.object(archive)
		if err != nil {
			return err
		}
		root := s.state.ReserveArchiveRoot
		for _, owner := range reserveArchiveOwnersV2(archive) {
			ref, e := reserveArchiveBundleRefV2(archive.Lineage, owner, hash)
			if e != nil {
				return e
			}
			root, e = s.reserveArchiveInsertV2(root, 0, "", ref)
			if e != nil {
				return e
			}
		}
		st := clone(s.state)
		st.ReserveArchiveRoot = root
		var facts v2ReserveFinality
		if s.readObject(archive.FinalWork, &facts) != nil {
			return ErrRecovery
		}
		if facts.Version == 2 {
			addFeatureV2(&st, v2ReserveCompensationFeature)
		}
		if err = s.publish(st); err != nil {
			return err
		}
		if err = s.point("reserve_archive_selected"); err != nil {
			return err
		}
	}
	if validateArchiveFinalityV2(archive, s.state, s.readObject) != nil {
		return ErrRecovery
	}
	// A replay after a partial retirement must retain the same pair: changing
	// either selector would change the physical CAS proof digest.
	current, prior, err := s.closedReserveSelectionsV2(archive)
	if err != nil {
		if !errors.Is(err, errReserveAnchorV2) {
			return err
		}
		if err = s.publish(clone(s.state)); err != nil {
			return err
		}
		current, prior, err = s.closedReserveSelectionsV2(archive)
		if err != nil {
			return err
		}
	}
	if err = s.point("reserve_archive_anchored"); err != nil {
		return err
	}
	hash, err := reserveArchiveHashV2(archive)
	if err != nil {
		return err
	}
	for _, entry := range archive.Entries {
		scope := active.Bundle.Scope
		if active.Bundle.PlanScope != nil {
			scope = *active.Bundle.PlanScope
		}
		if entry.Scope != nil {
			scope = *entry.Scope
		} else if entry.Claim.Owner != scope.Bundle {
			scope = m.archiveOwnerScope(archive, entry.Claim.Owner)
		}
		scope.Bundle = entry.Claim.Owner
		proof := reserveRetirementProofV2(scope, hash, archive, current, prior)
		if err = m.pool(entry.Claim.Role).RetireCAS(recoveryreserve.ExpectedV2{Claim: entry.Claim, Written: entry.Binding}, proof); err != nil {
			return ErrRecovery
		}
		if err = s.point("reserve_role_retired"); err != nil {
			return err
		}
	}
	for _, claim := range archive.UnusedEscrow {
		scope := active.Bundle.Scope
		scope.Bundle = claim.Owner
		if active.Bundle.PlanScope != nil {
			scope = *active.Bundle.PlanScope
			scope.Bundle = claim.Owner
		}
		if err = m.pool(claim.Role).RetireCAS(recoveryreserve.ExpectedV2{Claim: claim}, reserveRetirementProofV2(scope, hash, archive, current, prior)); err != nil {
			return ErrRecovery
		}
		if err = s.point("reserve_escrow_retired"); err != nil {
			return err
		}
	}
	if err = s.point("reserve_physical_retired"); err != nil {
		return err
	}
	return s.releaseArchivedReserveV2(archive)
}

func reserveArchiveOwnersV2(archive v2ReserveArchive) []string {
	owners := map[string]bool{}
	for _, entry := range archive.Entries {
		owners[entry.Claim.Owner] = true
	}
	for _, claim := range archive.UnusedEscrow {
		owners[claim.Owner] = true
	}
	result := make([]string, 0, len(owners))
	for owner := range owners {
		result = append(result, owner)
	}
	sort.Strings(result)
	return result
}

func reserveArchiveHashV2(archive v2ReserveArchive) (string, error) {
	_, hash, err := encodeReserveArchiveV2(archive)
	return hash, err
}

type reserveArchiveIdentityV2 struct {
	entry v2ReserveArchiveEntry
	kind  string
}

func reserveArchiveIdentitiesV2(archive v2ReserveArchive) []reserveArchiveIdentityV2 {
	result := []reserveArchiveIdentityV2{}
	for _, entry := range archive.Entries {
		result = append(result, reserveArchiveIdentityV2{entry, "claim"})
		if entry.Binding != nil {
			result = append(result, reserveArchiveIdentityV2{entry, "binding"})
		}
	}
	for _, claim := range archive.UnusedEscrow {
		result = append(result, reserveArchiveIdentityV2{v2ReserveArchiveEntry{Claim: claim}, "claim"})
	}
	return result
}

func (m *v2ReserveManager) archiveOwnerScope(archive v2ReserveArchive, owner string) recoveryreserve.ScopeV2 {
	for _, entry := range archive.Entries {
		if entry.Claim.Owner == owner && entry.Claim.Role == recoveryreserve.PlanV2 && entry.Scope != nil {
			return *entry.Scope
		}
	}
	for _, entry := range archive.Entries {
		if entry.Claim.Owner == owner && entry.Scope != nil {
			return *entry.Scope
		}
	}
	return recoveryreserve.ScopeV2{}
}

func reserveRetirementProofV2(scope recoveryreserve.ScopeV2, hash string, archive v2ReserveArchive, current, prior recoveryreserve.SelectionProofV2) recoveryreserve.RetirementProofV2 {
	work := scope.Operation
	finality := "operation_final"
	resolution := ""
	if scope.Kind != "operation" {
		work = scope.Recovery
		finality = "recovery_final"
	}
	if scope.Lease != "" {
		finality = "lease_resolved"
		resolution = archive.LeaseResolution
	}
	return recoveryreserve.RetirementProofV2{Scope: scope, Archive: hash, FinalAudit: archive.Audit, FinalWork: work, Finality: finality, LeaseResolution: resolution, Current: current, Previous: prior}
}

func (m *v2ReserveManager) archiveBundle(s *v2Store, bundle *v2ReserveBundle) ([]v2ReserveArchiveEntry, error) {
	if m.verifyBundle(s, bundle) != nil {
		return nil, ErrRecovery
	}
	entries := []v2ReserveArchiveEntry{}
	for _, claim := range bundle.Claims.all() {
		entry := v2ReserveArchiveEntry{Claim: claim}
		candidate, err := m.pool(claim.Role).InspectClaimed(claim)
		if err != nil {
			if !errors.Is(err, recoveryreserve.ErrConflict) || claim.Role == recoveryreserve.AdmissionV2 || (claim.Role == recoveryreserve.PlanV2 && bundle.Plan != nil) {
				return nil, ErrRecovery
			}
		} else {
			entry.Binding = &candidate.Binding
			entry.Raw = append([]byte{}, candidate.Bytes...)
			switch claim.Role {
			case recoveryreserve.AdmissionV2:
				entry.Scope = clone(&bundle.Scope)
			case recoveryreserve.PlanV2:
				var plan v2ReservePlan
				if checkpointDecode(entry.Raw, &plan) != nil {
					return nil, ErrRecovery
				}
				entry.Scope = &plan.Scope
			case recoveryreserve.EmergencyV2:
				var emergency v2ReserveEmergency
				if checkpointDecode(entry.Raw, &emergency) != nil {
					return nil, ErrRecovery
				}
				entry.Scope = &emergency.Scope
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (m *v2ReserveManager) buildTerminalArchive(s *v2Store, active v2ActiveReserve) (v2ReserveArchive, error) {
	archive := v2ReserveArchive{Format: v2Format, Version: 1, Lineage: s.state.Lineage, Origin: active.Work, Dependencies: []string{}}
	facts := v2ReserveFinality{Format: v2Format, Version: 1, Lineage: s.state.Lineage, Origin: v2ReserveWorkRef{ID: active.Work}}
	bundles := []*v2ReserveBundle{active.Bundle}
	if active.Bundle.PlanIntent != nil && active.Bundle.PlanIntent.DHCPWork != "" {
		d := s.state.RoutedDHCP
		if !routedDHCPTerminalV3(d) || !reserveJSONEqualV2(d.Bundle, active.Bundle) || validateRoutedDHCPSelectedV3(s.state, s.readObject) != nil {
			return archive, ErrRecovery
		}
		facts.Kind = v3RoutedDHCPKind
		var err error
		facts.Origin.Object, err = s.object(d)
		if err != nil {
			return archive, err
		}
		archive.Audit = d.Audit
	} else if active.Bundle.Scope.Kind == "boot" {
		facts.Kind = "system"
		record, err := (&v2Coordinator{store: s}).recoveryLookupLocked(active.Work)
		if err != nil || record.State != "final" || record.Pinned || !reflect.DeepEqual(record.Reserve, active.Bundle) {
			return archive, ErrRecovery
		}
		facts.Origin.Object, err = s.object(record)
		if err != nil {
			return archive, err
		}
		archive.Audit = record.Audit
	} else {
		facts.Kind = "operation"
		origin, err := s.lookupRetained(active.Bundle.Scope.Subject, active.Work)
		if err != nil || !terminalReserveOperationV2(origin, s.state) {
			return archive, ErrRecovery
		}
		facts.Origin.Object, err = s.object(origin)
		if err != nil {
			return archive, err
		}
		archive.Audit = origin.Outcome.AuditHash
		creditIndex := closingCreditIndexV2(&s.state, origin.ID)
		if creditIndex >= 0 {
			credit := s.state.ClosingCredits[creditIndex]
			if credit.Child != "" {
				child, e := s.lookupRetained(origin.Subject, credit.Child)
				if e != nil {
					return archive, e
				}
				if child.State == "accepted" {
					st := clone(s.state)
					if e = s.withoutEffects(&st, child, "ANDEIVA_CONFIRMATION_RESOLVED", s.state.Clock); e != nil {
						return archive, e
					}
					if e = s.publish(st); e != nil {
						return archive, e
					}
					child, e = s.lookupRetained(origin.Subject, credit.Child)
					if e != nil {
						return archive, e
					}
				}
				if !terminalReserveOperationV2(child, s.state) || child.Reserve == nil {
					return archive, ErrRecovery
				}
				hash, e := s.object(child)
				if e != nil {
					return archive, e
				}
				facts.Child = &v2ReserveWorkRef{ID: child.ID, Object: hash}
				archive.Child = child.ID
				archive.Audit = child.Outcome.AuditHash
				bundles = append(bundles, child.Reserve)
			} else if origin.Reserve.ClosingEscrow != nil {
				archive.UnusedEscrow = origin.Reserve.ClosingEscrow.all()
			}
		}
		if origin.Outcome.ConfirmationLease == "" && origin.Reserve != nil && origin.Reserve.PlanScope != nil && origin.Reserve.PlanScope.Lease != "" {
			resolution, e := reserveCompensationResolutionV2(origin)
			if e != nil {
				return archive, e
			}
			hash, e := s.object(resolution)
			if e != nil {
				return archive, e
			}
			facts.Version, facts.Resolution, archive.LeaseResolution = 2, hash, hash
		}
		if origin.Outcome.ConfirmationLease != "" {
			resolution := v2ReserveLeaseResolution{Format: v2Format, Version: 1, Origin: origin.ID, Lease: origin.Outcome.ConfirmationLease, Deadline: *origin.Outcome.ConfirmationDeadline, Child: archive.Child}
			if cfg := s.state.Configuration; cfg != nil && cfg.LastRecovery != "" {
				var record v2RecoveryRecord
				if s.readObject(cfg.LastRecovery, &record) != nil {
					return archive, ErrRecovery
				}
				if record.Origin == origin.ID && record.Lease == resolution.Lease && record.State == "final" {
					hash, e := s.object(record)
					if e != nil {
						return archive, e
					}
					facts.Recovery = &v2ReserveWorkRef{ID: record.ID, Object: hash}
					resolution.Recovery = record.ID
					archive.Audit = record.Audit
				}
			}
			hash, e := s.object(resolution)
			if e != nil {
				return archive, e
			}
			facts.Resolution = hash
			archive.LeaseResolution = hash
		}
	}
	for _, bundle := range bundles {
		entries, e := m.archiveBundle(s, bundle)
		if e != nil {
			return archive, e
		}
		archive.Entries = append(archive.Entries, entries...)
	}
	dependencies := map[string]bool{}
	for _, entry := range archive.Entries {
		if entry.Binding != nil && entry.Claim.Role == recoveryreserve.PlanV2 {
			var plan v2ReservePlan
			if checkpointDecode(entry.Raw, &plan) != nil {
				return archive, ErrRecovery
			}
			dependencies[plan.Intent.Previous] = true
			dependencies[plan.Intent.Target] = true
		}
	}
	for hash := range dependencies {
		archive.Dependencies = append(archive.Dependencies, hash)
	}
	hash, err := s.object(facts)
	if err != nil {
		return archive, err
	}
	archive.FinalWork = hash
	sortReserveArchiveV2(&archive)
	if _, _, err := encodeReserveArchiveV2(archive); err != nil {
		return archive, err
	}
	proofState := clone(s.state)
	if facts.Version == 2 {
		addFeatureV2(&proofState, v2ReserveCompensationFeature)
	}
	if validateArchiveFinalityV2(archive, proofState, s.readObject) != nil {
		return archive, ErrRecovery
	}
	return archive, nil
}

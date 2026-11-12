package configpoc

import (
	"errors"
	"reflect"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

var errReserveAnchorV2 = errors.New("ANDEIVA_RESERVE_ARCHIVE_ANCHOR_PENDING")

// This is a scoped retirement proof, not a general reachability/GC permit.
// Store.mu and the existing directory writer flock remain held throughout.
func (s *v2Store) closedReserveSelectionsV2(archive v2ReserveArchive) (recoveryreserve.SelectionProofV2, recoveryreserve.SelectionProofV2, error) {
	var current, previous recoveryreserve.SelectionProofV2
	data, err := checkpointRead(s.root, "selected.json", 4096)
	var selector v2Selector
	if err != nil || checkpointDecode(data, &selector) != nil || selector != s.selector || selector.Previous == "" {
		return current, previous, ErrRecovery
	}
	var currentSelection, priorSelection v2Selection
	if s.readObject(selector.Current, &currentSelection) != nil || s.readObject(selector.Previous, &priorSelection) != nil || !v2ValidSelection(currentSelection) || !v2ValidSelection(priorSelection) || currentSelection.Previous != selector.Previous || currentSelection.Sequence != priorSelection.Sequence+1 || currentSelection.Lineage != priorSelection.Lineage || currentSelection != s.selection {
		return current, previous, ErrRecovery
	}
	if currentSelection.Checkpoint {
		if priorSelection.Segment != 64 {
			return current, previous, ErrRecovery
		}
	} else if currentSelection.Segment != priorSelection.Segment+1 {
		return current, previous, ErrRecovery
	}
	var now, before v2State
	if s.readObject(currentSelection.State, &now) != nil || s.readObject(priorSelection.State, &before) != nil || !v2ValidState(now) || !v2ValidState(before) || now.Lineage != currentSelection.Lineage || before.Lineage != now.Lineage || !reflect.DeepEqual(now, s.state) || !preservesFeaturesV2(before, now) || !preservesReclamationV2(before, now) || !preservesRecoveryReserveV2(before, now) {
		return current, previous, ErrRecovery
	}
	for i, state := range []v2State{now, before} {
		if cfg := state.Configuration; cfg != nil && (cfg.Intent != nil || cfg.RecoveryRequired || cfg.Pending != nil) {
			return current, previous, ErrRecovery
		}
		if state.ReserveArchiveRoot == "" {
			return current, previous, errReserveAnchorV2
		}
		for _, identity := range reserveArchiveIdentitiesV2(archive) {
			actual, known, e := s.reserveArchiveBundleLookupV2(state.ReserveArchiveRoot, identity.entry, identity.kind)
			if e != nil {
				return current, previous, e
			}
			if !known {
				return current, previous, errReserveAnchorV2
			}
			if !reflect.DeepEqual(actual, archive) || validateArchiveFinalityV2(actual, state, s.readObject) != nil {
				return current, previous, ErrRecovery
			}
		}
		selection := currentSelection
		hash := selector.Current
		if i == 1 {
			selection = priorSelection
			hash = selector.Previous
		}
		proof := recoveryreserve.SelectionProofV2{Selection: hash, State: selection.State, Sequence: selection.Sequence, Lineage: selection.Lineage, ArchiveRoot: state.ReserveArchiveRoot}
		if i == 0 {
			current = proof
		} else {
			previous = proof
		}
	}
	// Never qualify a pair read across a selector replacement, including a
	// caller violating the writer-lease contract outside this process.
	again, e := checkpointRead(s.root, "selected.json", 4096)
	var final v2Selector
	if e != nil || checkpointDecode(again, &final) != nil || final != selector {
		return current, previous, ErrRecovery
	}
	return current, previous, nil
}

func (s *v2Store) releaseArchivedReserveV2(archive v2ReserveArchive) error {
	st := clone(s.state)
	owners := map[string]bool{archive.Origin: true}
	if archive.Child != "" {
		owners[archive.Child] = true
	}
	kept := make([]v2ActiveReserve, 0, len(st.ActiveReserves))
	held := uint64(0)
	for _, active := range st.ActiveReserves {
		if owners[active.Work] {
			if active.CanonicalHeld {
				held++
			}
			continue
		}
		kept = append(kept, active)
	}
	st.ActiveReserves = kept
	if st.SystemBundle != nil && st.SystemBundle.Work == archive.Origin {
		if !st.SystemBundle.CanonicalHeld {
			return ErrRecovery
		}
		held++
		st.SystemBundle = nil
	}
	if b := st.RoutedBootBoundary; b != nil && b.CompletedBoot != "" && b.Resolution != "" {
		if b.OldBoot != nil && b.OldBoot.ID == archive.Origin {
			held++
			st.RoutedBootBoundary = nil
		} else if b.Origin != nil && b.Origin.ID == archive.Origin {
			st.RoutedBootBoundary = nil
		}
	}
	if held == 0 || st.ReservedBytes < held*v2OperationReserveBytes || st.ReservedInodes < held*v2OperationReserveInodes {
		return ErrRecovery
	}
	st.ReservedBytes -= held * v2OperationReserveBytes
	st.ReservedInodes -= held * v2OperationReserveInodes
	if i := closingCreditIndexV2(&st, archive.Origin); i >= 0 {
		credit := st.ClosingCredits[i]
		if credit.Child != archive.Child || st.ReservedBytes < v2ClosingReserveBytes || st.ReservedInodes < v2ClosingReserveInodes {
			return ErrRecovery
		}
		st.ClosingCredits = append(st.ClosingCredits[:i], st.ClosingCredits[i+1:]...)
		st.ReservedBytes -= v2ClosingReserveBytes
		st.ReservedInodes -= v2ClosingReserveInodes
		for j := range st.Namespaces {
			if st.Namespaces[j].ClosingOrigin == archive.Origin {
				if len(st.Namespaces[j].ClosingOpen) != 0 {
					return ErrRecovery
				}
				st.Namespaces[j].ClosingOrigin = ""
				st.Namespaces[j].Closed = true
			}
		}
	}
	return s.publish(st)
}

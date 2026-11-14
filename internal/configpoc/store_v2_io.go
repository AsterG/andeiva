package configpoc

import (
	"bytes"
	"encoding/json"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"io"
	"os"
	"strings"
	"sync"
)

type v2Store struct {
	afterPublication    func()
	archiveObserver     func(v2ReserveArchiveRef) error
	access              *recoveryreserve.ReaderAccessV2
	readOnly            bool
	recordReader        func(string, int64) ([]byte, error)
	objectReader        func(string, any) error
	preparingShared     bool
	dhcpServerSupported bool // Trusted routed authority capability; never wire input.
	guardDeadlines      bool // Trusted opt-in assembly only; never persisted authority.
	reserves            *v2ReserveManager
	mu                  sync.Mutex
	root                *os.Root
	lock                *os.File
	state               v2State
	selection           v2Selection
	selector            v2Selector
	budget              v2Budget
	used                v2Budget
	blocked             bool
	hook                func(string) error
	allowance           v2Budget
	physical            v2PhysicalUsage
	spaceProbe          func(*os.File) (storageSpace, error)
	reclaim             *v2ReclaimSession
}

// The caller owns the directory lifetime. No directory, legacy layout or engine
// is created or changed here. A failed ambiguous publication fences this handle.
func openV2(area *os.Root, budget v2Budget) (*v2Store, error) {
	return openV2BeforeLock(area, budget, nil)
}

func openV2BeforeLock(area *os.Root, budget v2Budget, beforeLock func() error) (*v2Store, error) {
	s, err := v2AreaWithAccess(area, budget, beforeLock, nil)
	if err != nil {
		return nil, err
	}
	if err = s.readSelection(); err != nil {
		_ = s.lock.Close()
		return nil, err
	}
	return s, nil
}

func createV2(area *os.Root, budget v2Budget, initial v2State) (*v2Store, error) {
	s, err := prepareV2(area, budget, initial)
	if err != nil {
		return nil, err
	}
	if err = s.publish(s.state); err != nil {
		_ = s.lock.Close()
		return nil, err
	}
	return s, nil
}

func prepareV2(area *os.Root, budget v2Budget, initial v2State) (*v2Store, error) {
	return prepareV2BeforeLock(area, budget, initial, nil)
}

func prepareV2BeforeLock(area *os.Root, budget v2Budget, initial v2State, beforeLock func() error) (*v2Store, error) {
	if area == nil {
		return nil, errV2Invalid
	}
	// Refuse unknown/legacy entries before creating the lock.
	dir, err := area.Open(".")
	if err != nil {
		return nil, errV2Unavailable
	}
	entries, readErr := dir.ReadDir(1)
	closeErr := dir.Close()
	if len(entries) != 0 || readErr != io.EOF || closeErr != nil {
		return nil, errV2Unavailable
	}
	s, err := v2AreaBeforeLock(area, budget, beforeLock)
	if err != nil {
		return nil, err
	}
	// The empty preflight is not a creation lease. Another initializer may
	// publish before this lock is acquired; never replace its selected state.
	lockedDirectory, err := area.Open(".")
	if err != nil {
		_ = s.lock.Close()
		return nil, errV2Unavailable
	}
	lockedEntries, lockedReadErr := lockedDirectory.ReadDir(2)
	lockedCloseErr := lockedDirectory.Close()
	if (lockedReadErr != nil && lockedReadErr != io.EOF) || lockedCloseErr != nil || len(lockedEntries) != 1 || lockedEntries[0].Name() != "checkpoint.lock" {
		_ = s.lock.Close()
		return nil, errV2Unavailable
	}
	if initial.SubjectSlots == 0 {
		initial.SubjectSlots = v2MaximumSubjects
	}
	if initial.NamespaceSlots == 0 {
		initial.NamespaceSlots = v2MaximumNamespaces
	}
	if initial.SubjectSequence == 0 {
		initial.SubjectSequence = uint64(len(initial.Subjects))
	}
	if initial.Format != v2Format || initial.Generation != 1 || initial.HighWater != 0 || initial.Index != "" || initial.Operational || !v2ValidState(initial) {
		_ = s.lock.Close()
		return nil, errV2Invalid
	}
	s.state = initial
	return s, nil
}

func v2Area(area *os.Root, budget v2Budget) (*v2Store, error) {
	return v2AreaBeforeLock(area, budget, nil)
}

func v2AreaBeforeLock(area *os.Root, budget v2Budget, beforeLock func() error) (*v2Store, error) {
	return v2AreaWithAccess(area, budget, beforeLock, nil)
}
func v2AreaWithAccess(area *os.Root, budget v2Budget, beforeLock func() error, access *recoveryreserve.ReaderAccessV2) (*v2Store, error) {
	if area == nil || budget.Bytes < 4*v2OperationReserveBytes || budget.Bytes > 1<<40 || budget.Inodes < 256 || budget.Inodes > 1<<26 {
		return nil, errV2Invalid
	}
	if access != nil {
		pinned := *access
		access = &pinned
	}
	s := &v2Store{root: area, budget: budget, access: access}
	// This preflight prevents creating a lock in a foreign layout. Its counts
	// are not authoritative: an active writer can change the store afterwards.
	if err := s.scanV2Area(); err != nil {
		return nil, err
	}
	if beforeLock != nil {
		if err := beforeLock(); err != nil {
			return nil, err
		}
	}
	var err error
	s.lock, err = s.lockSharedProfileV2()
	if err != nil {
		return nil, err
	}
	if err = s.scanV2Area(); err != nil {
		_ = s.lock.Close()
		return nil, err
	}
	return s, nil
}

func (s *v2Store) scanV2Area() error {
	dir, err := s.recordDirectoryV2()
	if err != nil {
		return errV2Unavailable
	}
	s.used = v2Budget{}
	s.blocked = false
	initial, err := dir.Stat()
	if err != nil {
		_ = dir.Close()
		return errV2Unavailable
	}
	s.physical = v2PhysicalUsage{inodes: 1, directoryInfo: initial}
	s.physical.directory, err = v2Allocated(initial)
	if err != nil {
		_ = dir.Close()
		return err
	}
	for {
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			name := entry.Name()
			if name != "checkpoint.lock" && name != "selected.json" && name != "selection.pending" && !(strings.HasPrefix(name, "object-") && strings.HasSuffix(name, ".json") && len(name) == 76 && v2HashPattern.MatchString(name[7:71])) {
				_ = dir.Close()
				return errV2Unavailable
			}
			info, statErr := s.root.Lstat(name)
			if statErr != nil || !s.recordMetadataV2(name, info, v2ObjectLimit) {
				_ = dir.Close()
				return errV2Unavailable
			}
			info, statErr = s.physicalRecord(name, info)
			if statErr != nil {
				_ = dir.Close()
				return errV2Unavailable
			}
			size := info.Size()
			if size < 0 || s.physicalAddFile(info) != nil {
				_ = dir.Close()
				return errV2Unavailable
			}
			if name == "selected.json" {
				s.physical.selector, _ = v2Allocated(info)
				s.physical.selectorSize = uint64(size)
			}
			s.used.Bytes += uint64(size)
			s.used.Inodes++
			if name == "selection.pending" {
				s.blocked = true
			}
			if s.used.Bytes > s.budget.Bytes || s.used.Inodes > s.budget.Inodes {
				_ = dir.Close()
				return errV2Unavailable
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = dir.Close()
			return errV2Unavailable
		}
	}
	final, statErr := dir.Stat()
	closeErr := dir.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(initial, final) || initial.Size() != final.Size() || !initial.ModTime().Equal(final.ModTime()) {
		return errV2Unavailable
	}
	return nil
}

func (s *v2Store) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocked = true
	return s.lock.Close()
}

func v2ValidState(st v2State) bool {
	if st.RecoveryReserveVersion == 1 && !reserveMetadataStateFitsV2(st) {
		return false
	}
	if st.ReclamationVersion > 1 {
		return false
	}
	if !validFeaturesV2(st) {
		return false
	}
	if st.Format != v2Format || st.Lineage == "" || len(st.Lineage) > 128 || st.Generation == 0 || (st.LiveSlots != 64 && st.LiveSlots != 4096 && st.LiveSlots != v2MaximumOperations) || st.SubjectSlots == 0 || st.SubjectSlots > v2MaximumSubjects || st.NamespaceSlots == 0 || st.NamespaceSlots > v2MaximumNamespaces || uint64(len(st.Subjects)) > st.SubjectSlots || uint64(len(st.Namespaces)) > st.NamespaceSlots || st.Clock.IsZero() || st.Clock.Location().String() != "UTC" || st.Operational {
		return false
	}
	if st.Index != "" && !v2HashPattern.MatchString(st.Index) {
		return false
	}
	if (st.HighWater == 0) != (st.Index == "") || (st.Migration != "" && !v2HashPattern.MatchString(st.Migration)) {
		return false
	}
	if st.Configuration != nil && !validV2Configuration(st.Configuration) {
		return false
	}
	if st.RoutedBootBoundary != nil && (st.RecoveryReserveVersion != 1 || !hasFeatureV2(st, v2RoutedBootBoundaryFeature) || !validRoutedBootBoundaryShapeV2(st.RoutedBootBoundary)) {
		return false
	}
	ids, logins := map[string]bool{}, map[string]bool{}
	for _, sub := range st.Subjects {
		if sub.ID == "" || len(sub.ID) > 128 || sub.Login == "" || len(sub.Login) > 128 || !v2HashPattern.MatchString(sub.CredentialRevision) || ids[sub.ID] || (!sub.Retired && logins[sub.Login]) {
			return false
		}
		ids[sub.ID] = true
		if !sub.Retired {
			logins[sub.Login] = true
		}
	}
	names := map[string]bool{}
	var reserved uint64
	for _, ns := range st.Namespaces {
		if ns.ID == "" || len(ns.ID) > 128 || names[ns.ID] || !ids[ns.Subject] || !configurationDomainV2(ns.Domain, hasFeatureV2(st, v2RoutedFeature)) || ns.AdmitUntil.IsZero() || len(ns.Open) > v2MaximumOpen {
			return false
		}
		names[ns.ID] = true
		seen := map[string]bool{}
		for _, id := range ns.Open {
			if id == "" || len(id) > 128 || seen[id] {
				return false
			}
			seen[id] = true
			reserved++
		}
	}
	if st.Configuration != nil && st.Configuration.Intent != nil && st.Configuration.Intent.Kind == v2BootKind {
		reserved++
	}
	held, ok := reserveHeldReservationsV2(st)
	if !ok {
		return false
	}
	reserved += held
	return validClosingStateV2(st, reserved)
}

func (s *v2Store) readObject(hash string, value any) error {
	if s.objectReader != nil {
		err := s.objectReader(hash, value)
		if err != nil {
			s.blocked = true
		}
		return err
	}
	name, err := v2ObjectName(hash)
	if err != nil {
		s.blocked = true
		return err
	}
	data, err := s.readRecordV2(name, v2ObjectLimit)
	if err != nil || checkpointDigest(data) != hash || checkpointDecode(data, value) != nil {
		s.blocked = true
		return errV2Unavailable
	}
	return nil
}

func (s *v2Store) point(name string) error {
	if s.hook != nil {
		if err := s.hook(name); err != nil {
			return err
		}
	}
	return nil
}

// Content addressing permits safe deduplication only after exact readback.
// O_EXCL prevents replacing another writer's object, even after a guard race.
func (s *v2Store) object(value any) (string, error) {
	return s.objectClass(value, false)
}

func (s *v2Store) objectClass(value any, indexPage bool) (string, error) {
	if s.readOnly {
		return "", errV2Unavailable
	}
	if !indexPage {
		s.revokeReclaimGeneric(value)
	}
	data, hash, err := v2Canonical(value)
	if err != nil {
		return "", err
	}
	// A promoted parent can retain descendants outside the selected closure.
	// Revoke the whole session authority rather than guessing a partial closure.
	if !indexPage && s.reclaim != nil {
		if _, tracked := s.reclaim.pages[hash]; tracked {
			s.revokeReclaimAuthority()
		}
	}
	name, _ := v2ObjectName(hash)
	if _, err = s.root.Lstat(name); err == nil {
		if indexPage && s.reclaim != nil {
			// The parent itself may have been untracked at the ledger cap while
			// its newly created children are still tracked.
			s.revokeReclaimAuthority()
		}
		prior, e := s.readRecordV2(name, v2ObjectLimit)
		if e != nil || !bytes.Equal(prior, data) {
			return "", errV2Unavailable
		}
		// An orphan from a prior process may have complete bytes without a
		// successful fsync. Exact readback alone does not establish durability.
		file, e := openRecordFile(s.root, name)
		if e != nil {
			return "", errV2Unavailable
		}
		expected, statErr := file.Stat()
		syncErr := file.Sync()
		closeErr := file.Close()
		if statErr != nil || syncErr != nil || closeErr != nil {
			return "", errV2Unavailable
		}
		verified, e := s.readPinnedRecordV2(name, v2ObjectLimit, expected)
		if e != nil || !bytes.Equal(verified, data) {
			return "", errV2Unavailable
		}
		return hash, nil
	} else if !os.IsNotExist(err) {
		return "", errV2Unavailable
	}
	// Historical immutable objects retain their existing read/dedup contract.
	// New reserve-profile writes must fit the per-object lifecycle envelope.
	if s.state.RecoveryReserveVersion == 1 && len(data) > reserveMetadataObjectLimitV2 {
		return "", errV2Limited
	}
	reservedBytes := s.state.ReservedBytes - s.allowance.Bytes
	reservedInodes := s.state.ReservedInodes - s.allowance.Inodes
	if s.used.Bytes+reservedBytes+uint64(len(data)) > s.budget.Bytes || s.used.Inodes+reservedInodes+1 > s.budget.Inodes {
		return "", errV2Limited
	}
	if err = s.physicalCapacity(uint64(len(data)), 1); err != nil {
		return "", err
	}
	f, err := s.createRecordV2(name)
	if err != nil {
		return "", errV2Unavailable
	}
	s.used.Inodes++
	s.used.Bytes += uint64(len(data))
	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = s.point("object_written")
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if writeErr == nil {
		writeErr = s.point("object_synced")
	}
	info, statErr := f.Stat()
	closeErr := f.Close()
	if writeErr != nil || statErr != nil || closeErr != nil {
		s.blocked = true
		return "", errV2Unavailable
	}
	if err = s.physicalAddFile(info); err != nil {
		s.blocked = true
		return "", err
	}
	verified, err := s.readPinnedRecordV2(name, v2ObjectLimit, info)
	if err != nil || !bytes.Equal(verified, data) {
		s.blocked = true
		return "", errV2Unavailable
	}
	if err = s.physicalRefreshDirectory(); err != nil {
		s.blocked = true
		return "", err
	}
	if indexPage {
		s.rememberReclaimPage(hash, info)
	}
	return hash, nil
}

func (s *v2Store) readSelection() error {
	// Decode into fresh values: omitted optional fields must not survive a
	// reconciliation read into a previously populated in-memory selection.
	var selector v2Selector
	var selection v2Selection
	var selectedState v2State
	data, err := s.readRecordV2("selected.json", 4096)
	if err != nil || checkpointDecode(data, &selector) != nil || selector.Format != v2Format {
		return errV2Unavailable
	}
	if err = s.readObject(selector.Current, &selection); err != nil {
		return err
	}
	if !v2ValidSelection(selection) || selection.Previous != selector.Previous {
		return errV2Unavailable
	}
	if err = s.readObject(selection.State, &selectedState); err != nil || !v2ValidState(selectedState) || selectedState.Lineage != selection.Lineage {
		return errV2Unavailable
	}
	// Verify the bounded active delta segment and previous complete selection.
	current := selection
	currentState := selectedState
	for i := uint64(1); current.Previous != "" && i <= 64; i++ {
		var prior v2Selection
		if err = s.readObject(current.Previous, &prior); err != nil || !v2ValidSelection(prior) || prior.Lineage != current.Lineage || prior.Sequence+1 != current.Sequence {
			return errV2Unavailable
		}
		var state v2State
		if err = s.readObject(prior.State, &state); err != nil || !v2ValidState(state) || state.Lineage != prior.Lineage || !preservesFeaturesV2(state, currentState) || !preservesReclamationV2(state, currentState) || !preservesRecoveryReserveV2(state, currentState) {
			return errV2Unavailable
		}
		if current.Checkpoint {
			if prior.Segment != 64 {
				return errV2Unavailable
			}
			break
		}
		if prior.Segment+1 != current.Segment {
			return errV2Unavailable
		}
		current = prior
		currentState = state
	}
	if selectedState.Index != "" {
		var page v2Page
		if s.readObject(selectedState.Index, &page) != nil || !v2ValidPage(page, 2) {
			return errV2Unavailable
		}
	}
	reader := &v2Store{root: s.root, state: selectedState, access: s.access, readOnly: s.readOnly, recordReader: s.recordReader, objectReader: s.objectReader}
	if validateRoutedBootBoundaryV2(selectedState, reader.readObject) != nil {
		return errV2Unavailable
	}
	if selectedState.Migration != "" && reader.validateMigration() != nil {
		return errV2Unavailable
	}
	if hasFeatureV2(selectedState, v2SharedReaderFeature) != (s.access != nil) {
		return errV2Unavailable
	}
	s.selector = selector
	s.selection = selection
	s.state = selectedState
	return nil
}

func v2ValidSelection(selection v2Selection) bool {
	if selection.Format != v2Format || selection.Sequence == 0 || selection.Segment == 0 || selection.Segment > 64 {
		return false
	}
	if selection.Sequence == 1 {
		return selection.Previous == "" && selection.Segment == 1 && !selection.Checkpoint
	}
	return selection.Previous != "" && selection.Checkpoint == (selection.Segment == 1)
}

func (s *v2Store) publish(state v2State) (result error) {
	// Every selected DHCP candidate/configuration carries the refusal feature,
	// including paths that publish a Stage without going through admission.
	if configurationHasDHCPServerV1(state.Configuration) {
		if !s.dhcpServerSupported {
			return ErrDenied
		}
		state.RequiredFeatures = append([]string(nil), state.RequiredFeatures...)
		addFeatureV2(&state, v1RoutedDHCPServerFeature)
	}

	if s.readOnly || (!s.preparingShared && hasFeatureV2(state, v2SharedReaderFeature) != (s.access != nil)) || s.blocked || s.selection.Sequence == ^uint64(0) || !v2ValidState(state) || !preservesFeaturesV2(s.state, state) || !preservesReclamationV2(s.state, state) || !preservesRecoveryReserveV2(s.state, state) || !s.preservesRoutedBootBoundaryStateV2(state) {
		return errV2Unavailable
	}
	if validateRoutedBootBoundaryV2(state, s.readObject) != nil {
		s.blocked = true
		return errV2Unavailable
	}
	// Registry growth must leave room for both outcomes of an outstanding
	// confirmation. Reject pressure before writes without fencing the store.
	if err := reserveMetadataFutureFitsV2(state, s.readObject); err != nil {
		if err != errV2Limited {
			s.blocked = true
		}
		return err
	}
	defer func() {
		if result != nil {
			s.blocked = true
		}
	}()
	// Earlier lifecycle writes or engine effects may precede publication, so
	// pressure here retains the original uncertainty fence. The old selector
	// remains counted while two new objects and its replacement coexist.
	if err := s.physicalCapacity(2*v2ObjectLimit+4096, 3); err != nil {
		return err
	}
	stateHash, err := s.object(state)
	if err != nil {
		return err
	}
	next := v2Selection{Format: v2Format, Lineage: state.Lineage, Sequence: s.selection.Sequence + 1, State: stateHash, Previous: s.selector.Current, Segment: s.selection.Segment + 1}
	if next.Segment > 64 {
		next.Segment = 1
		next.Checkpoint = true
	}
	selectionHash, err := s.object(next)
	if err != nil {
		return err
	}
	if s.syncRecordDirectoryV2() != nil || s.point("objects_durable") != nil {
		return errV2Unavailable
	}
	selector := v2Selector{Format: v2Format, Current: selectionHash, Previous: s.selector.Current}
	data, err := json.Marshal(selector)
	if err != nil {
		return errV2Unavailable
	}
	info, err := s.writeSelectorRecordV2(data)
	if err != nil {
		return errV2Unavailable
	}
	if err = s.physicalPendingSelector(info); err != nil {
		return err
	}
	if s.point("before_select") != nil {
		return errV2Unavailable
	}
	verified, err := s.readPinnedRecordV2("selection.pending", 4096, info)
	if err != nil || !bytes.Equal(data, verified) {
		return errV2Unavailable
	}
	if s.root.Rename("selection.pending", "selected.json") != nil {
		return errV2Unavailable
	}
	if s.point("after_select") != nil || s.syncRecordDirectoryV2() != nil {
		return errV2Uncertain
	}
	if err = s.physicalSelected(info); err != nil {
		return errV2Uncertain
	}
	s.state = state
	s.selection = next
	s.selector = selector
	if s.afterPublication != nil {
		s.afterPublication()
	}
	return nil
}

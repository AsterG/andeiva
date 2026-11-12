//go:build linux

package configpoc

import (
	"bytes"

	"golang.org/x/sys/unix"
)

// Only the unselected, fixed publication name is quarantined. Keeping its
// exact canonical bytes as an ordinary immutable object avoids unlink races
// and preserves evidence/allocation. No staged configuration is adopted.
func recoverReservePendingV2(s *v2Store, m *v2ReserveManager) (result error) {
	defer func() {
		if s != nil && result != nil {
			s.blocked = true
		}
	}()
	if s == nil || m == nil || s.state.RecoveryReserveVersion != 1 || !s.blocked || m.verifySelected(s) != nil {
		return ErrRecovery
	}
	info, err := s.root.Lstat("selection.pending")
	if err != nil || !regularOwned(info, 4096) {
		return ErrRecovery
	}
	data, err := checkpointReadPinned(s.root, "selection.pending", 4096, info)
	if err != nil {
		return ErrRecovery
	}
	var staged v2Selector
	if checkpointDecode(data, &staged) != nil || staged.Format != v2Format || staged.Previous != s.selector.Current || staged.Current == s.selector.Current {
		return ErrRecovery
	}
	encoded, _, err := v2Canonical(staged)
	if err != nil || !bytes.Equal(encoded, data) {
		return ErrRecovery
	}
	var selection v2Selection
	var state v2State
	if s.readObject(staged.Current, &selection) != nil || !v2ValidSelection(selection) || selection.Lineage != s.state.Lineage || selection.Previous != s.selector.Current || selection.Sequence != s.selection.Sequence+1 || s.readObject(selection.State, &state) != nil || !v2ValidState(state) || state.Lineage != s.state.Lineage || !preservesFeaturesV2(s.state, state) || !preservesReclamationV2(s.state, state) || !preservesRecoveryReserveV2(s.state, state) {
		return ErrRecovery
	}
	if selection.Checkpoint {
		if s.selection.Segment != 64 {
			return ErrRecovery
		}
	} else if selection.Segment != s.selection.Segment+1 {
		return ErrRecovery
	}
	selectorBytes, err := checkpointRead(s.root, "selected.json", 4096)
	var actual v2Selector
	if err != nil || checkpointDecode(selectorBytes, &actual) != nil || actual != s.selector {
		return ErrRecovery
	}
	name, err := v2ObjectName(checkpointDigest(data))
	if err != nil {
		return ErrRecovery
	}
	directory, err := s.physicalDirectory()
	if err != nil {
		return err
	}
	defer func() {
		if directory.Close() != nil {
			result = ErrRecovery
			s.blocked = true
		}
	}()
	if err = s.point("before_reserve_staging_quarantine"); err != nil {
		return err
	}
	if _, err = checkpointReadPinned(s.root, "selection.pending", 4096, info); err != nil {
		return ErrRecovery
	}
	fd := int(directory.Fd())
	s.revokeReclaimAuthority()
	if err = unix.Renameat2(fd, "selection.pending", fd, name, unix.RENAME_NOREPLACE); err != nil {
		return ErrRecovery
	}
	quarantined, err := checkpointReadPinned(s.root, name, 4096, info)
	if err != nil || !bytes.Equal(quarantined, data) {
		// A same-UID writer violating the flock contract is outside cooperative
		// serialization. Never remove/replace its bytes, including on mismatch.
		_ = unix.Renameat2(fd, name, fd, "selection.pending", unix.RENAME_NOREPLACE)
		_ = directory.Sync()
		return ErrRecovery
	}
	if s.point("after_reserve_staging_quarantine") != nil || directory.Sync() != nil {
		return ErrRecovery
	}
	oldSelector := s.selector
	if s.scanV2Area() != nil || s.blocked || s.readSelection() != nil || s.selector != oldSelector {
		return ErrRecovery
	}
	return nil
}

//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"golang.org/x/sys/unix"
)

const routedScopeRecordNameV3 = "grouped-scope-v3"

type routedScopeRecordSlotV3 struct {
	area           *os.Root
	writer, reader *os.File
}

// Installer-only reservation; managed startup never creates or resizes this slot.
func PrepareRoutedScopeRecoverySlotV3(ctx context.Context, c Config) error {
	if ctx == nil || ctx.Err() != nil || c.Validate() != nil || safeParents(routedRetirementDirectoryV3+"/"+routedScopeRecordNameV3) != nil {
		return ErrIdentity
	}
	area, err := os.OpenRoot(routedRetirementDirectoryV3)
	if err != nil {
		return err
	}
	defer area.Close()
	slot, err := openScopeRecordSlotV3(area, true)
	if err != nil {
		return err
	}
	return slot.Close()
}
func openScopeRecordSlotV3(area *os.Root, create bool) (out *routedScopeRecordSlotV3, result error) {
	if area == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrIdentity
	}
	directory, err := area.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	var st unix.Stat_t
	if unix.Fstat(int(directory.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 || st.Gid != 0 || !fenceNoACLV3(directory, true) {
		return nil, ErrIdentity
	}
	flags := os.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := area.OpenFile(routedScopeRecordNameV3, flags, 0600)
	created := create && err == nil
	if create && errors.Is(err, os.ErrExist) {
		file, err = area.OpenFile(routedScopeRecordNameV3, os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, err
	}
	s := &routedScopeRecordSlotV3{area: area, writer: file}
	defer func() {
		if result != nil {
			result = errors.Join(result, s.Close())
		}
	}()
	if unix.Fstat(int(file.Fd()), &st) != nil || st.Mode != unix.S_IFREG|0600 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 || !fenceNoACLV3(file, false) {
		return nil, ErrIdentity
	}
	if err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, err
	}
	if created {
		if err = unix.Fallocate(int(file.Fd()), 0, 0, RoutedScopeRecoveryRecordSizeV3); err != nil {
			return nil, err
		}
		if err = errors.Join(file.Sync(), directory.Sync()); err != nil {
			return nil, err
		}
	}
	s.reader, err = area.OpenFile(routedScopeRecordNameV3, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if err = s.same(); err != nil {
		return nil, err
	}
	raw, err := s.read()
	if err != nil {
		return nil, err
	}
	if !scopeRecordZeroV3(raw) {
		if _, err = DecodeRoutedScopeRecoveryV3(raw); err != nil {
			return nil, err
		}
	}
	return s, nil
}
func scopeRecordZeroV3(raw []byte) bool {
	return len(raw) == RoutedScopeRecoveryRecordSizeV3 && bytes.Equal(raw, make([]byte, RoutedScopeRecoveryRecordSizeV3))
}
func (s *routedScopeRecordSlotV3) same() error {
	if s == nil || s.reader == nil || s.writer == nil || validateScopeRecoveryRecordFileV3(s.reader) != nil {
		return ErrIdentity
	}
	a, e1 := s.reader.Stat()
	b, e2 := s.writer.Stat()
	current, e3 := s.area.Lstat(routedScopeRecordNameV3)
	if e1 != nil || e2 != nil || e3 != nil || !os.SameFile(a, b) || !os.SameFile(a, current) {
		return ErrIdentity
	}
	return nil
}
func (s *routedScopeRecordSlotV3) read() ([]byte, error) {
	if s.same() != nil {
		return nil, ErrIdentity
	}
	raw := make([]byte, RoutedScopeRecoveryRecordSizeV3)
	n, err := s.reader.ReadAt(raw, 0)
	if err != nil || n != len(raw) || s.same() != nil {
		return nil, ErrIdentity
	}
	return raw, nil
}
func (s *routedScopeRecordSlotV3) write(raw []byte) error {
	if len(raw) != RoutedScopeRecoveryRecordSizeV3 || s.same() != nil {
		return ErrIdentity
	}
	n, err := s.writer.WriteAt(raw, 0)
	if err != nil || n != len(raw) {
		return errors.Join(err, io.ErrShortWrite)
	}
	if err = s.writer.Sync(); err != nil {
		return err
	}
	after, err := s.read()
	if err != nil || !bytes.Equal(after, raw) {
		return errors.Join(err, ErrStorage)
	}
	return nil
}
func (s *routedScopeRecordSlotV3) publish(raw []byte) error {
	if _, err := DecodeRoutedScopeRecoveryV3(raw); err != nil {
		return err
	}
	old, err := s.read()
	if err != nil || !scopeRecordZeroV3(old) {
		return ErrIdentity
	}
	return s.write(raw)
}

// Reuse is permitted only after exact prior retirement and verified empty store.
// An unfinished manifest is never overwritten to make a new boot succeed.
func (s *routedScopeRecordSlotV3) clearCompleted(ctx context.Context, receipt *routedRetirementSlot) error {
	raw, err := s.read()
	if err != nil {
		return err
	}
	if scopeRecordZeroV3(raw) {
		return nil
	}
	r, err := DecodeRoutedScopeRecoveryV3(raw)
	if err != nil || receipt == nil || receipt.sameFile() != nil {
		return ErrIdentity
	}
	proof := make([]byte, RootRetirementReceiptSizeV3)
	if n, err := receipt.file.ReadAt(proof, 0); err != nil || n != len(proof) {
		return ErrIdentity
	}
	old, err := DecodeRootRetirementReceiptV3(proof)
	identity := networkexecutor.OwnedNamespaceIdentity{UID: r.Identities.HelperUID, GID: r.Identities.IPCGID, Namespace: r.Metadata.GatewayNamespace, Host: r.Metadata.HostNamespace, BootID: r.Metadata.BootID, RunID: r.Metadata.RunID}
	if err != nil || old.Old != identity || old.MetadataSHA256 != r.MetadataSHA256 {
		return ErrIdentity
	}
	stored, err := readScopeRecoveryStoreV3(ctx)
	if err != nil || !scopeRecoveryStoreMatchesV3(stored, nil) {
		return ErrIdentity
	}
	return s.write(make([]byte, RoutedScopeRecoveryRecordSizeV3))
}
func (s *routedScopeRecordSlotV3) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.reader != nil {
		err = s.reader.Close()
		s.reader = nil
	}
	if s.writer != nil {
		err = errors.Join(err, s.writer.Close())
		s.writer = nil
	}
	return err
}

package configpoc

import (
	"bytes"
	"context"
	"os"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

const v2SharedReaderFeature = "shared_reader.v1"

func (s *v2Store) readRecordV2(name string, limit int64) ([]byte, error) {
	if s.recordReader != nil {
		return s.recordReader(name, limit)
	}
	if s.access == nil {
		return checkpointRead(s.root, name, limit)
	}
	if limit < 1 || limit > v2ObjectLimit {
		return nil, errV2Unavailable
	}
	data, err := s.access.ReadFile(context.Background(), s.root, name, int(limit))
	if err != nil {
		return nil, errV2Unavailable
	}
	return data, nil
}

func (s *v2Store) recordMetadataV2(name string, info os.FileInfo, limit int64) bool {
	if s.access == nil || name == "checkpoint.lock" {
		return info != nil && regularOwned(info, limit)
	}
	actual, err := s.access.CheckFile(s.root, name, limit)
	return err == nil && info != nil && os.SameFile(info, actual) && info.Size() == actual.Size() && info.ModTime().Equal(actual.ModTime())
}

func (s *v2Store) sameProfileRecordV2(name string, before, after os.FileInfo) bool {
	if s.access == nil {
		return sameRecordFile(before, after)
	}
	return before != nil && after != nil && os.SameFile(before, after) && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) && s.recordMetadataV2(name, after, v2ObjectLimit)
}

func (s *v2Store) readPinnedRecordV2(name string, limit int64, expected os.FileInfo) ([]byte, error) {
	if s.access == nil {
		return checkpointReadPinned(s.root, name, limit, expected)
	}
	before, err := s.root.Lstat(name)
	if err != nil || !s.sameProfileRecordV2(name, expected, before) {
		return nil, errV2Unavailable
	}
	data, err := s.readRecordV2(name, limit)
	if err != nil {
		return nil, err
	}
	after, err := s.root.Lstat(name)
	if err != nil || !s.sameProfileRecordV2(name, expected, after) {
		return nil, errV2Unavailable
	}
	return data, nil
}

func (s *v2Store) writeSelectorRecordV2(data []byte) (info os.FileInfo, result error) {
	if s.access == nil {
		return checkpointWrite(s.root, "selection.pending", data, nil, "")
	}
	f, err := s.createRecordV2("selection.pending")
	if err != nil {
		return nil, err
	}
	defer func() {
		if f.Close() != nil {
			info, result = nil, errV2Unavailable
		}
	}()
	n, err := f.Write(data)
	if err != nil || n != len(data) || f.Sync() != nil {
		return nil, errV2Unavailable
	}
	info, err = f.Stat()
	if err != nil || !s.recordMetadataV2("selection.pending", info, 4096) {
		return nil, errV2Unavailable
	}
	actual, err := s.readPinnedRecordV2("selection.pending", 4096, info)
	if err != nil || !bytes.Equal(actual, data) {
		return nil, errV2Unavailable
	}
	return info, nil
}

func (s *v2Store) syncRecordDirectoryV2() error {
	if s.access == nil {
		return checkpointSync(s.root, nil, "")
	}
	f, err := s.recordDirectoryV2()
	if err != nil {
		return err
	}
	err = f.Sync()
	if f.Close() != nil {
		return errV2Unavailable
	}
	return err
}

func openSharedStoreV2(area *os.Root, budget v2Budget, access recoveryreserve.ReaderAccessV2) (*v2Store, error) {
	s, err := v2AreaWithAccess(area, budget, nil, &access)
	if err != nil {
		return nil, err
	}
	if err = s.readSelection(); err != nil {
		_ = s.lock.Close()
		return nil, err
	}
	return s, nil
}

// PrepareSharedReaderV2 records opt-in only. The caller must stop this service
// and perform a separately authorized offline conversion before shared reopen.
// Successful publication fences this private handle; no chmod is performed.
func (s *ServiceV2) PrepareSharedReaderV2(ctx context.Context) error {
	if s == nil || s.coordinator == nil || ctx == nil {
		return ErrInvalid
	}
	c := s.coordinator
	store := c.store
	store.mu.Lock()
	defer store.mu.Unlock()
	if ctx.Err() != nil || c.closed || store.blocked || store.access != nil || store.readOnly || store.state.Configuration == nil {
		return ErrRecovery
	}
	cfg := store.state.Configuration
	if cfg.Intent != nil || cfg.Pending != nil || cfg.RecoveryRequired {
		return ErrConflict
	}
	for _, ns := range store.state.Namespaces {
		if len(namespaceOpenIDsV2(ns)) != 0 {
			return ErrConflict
		}
	}
	if !c.readback(*cfg) || c.validateReferencesLocked() != nil {
		return ErrRecovery
	}
	st := clone(store.state)
	addFeatureV2(&st, v2SharedReaderFeature)
	store.preparingShared = true
	err := store.publish(st)
	store.preparingShared = false
	if err == nil {
		store.blocked = true
	}
	return err
}

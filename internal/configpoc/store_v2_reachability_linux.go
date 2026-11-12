//go:build linux

package configpoc

import (
	"os"
	"syscall"
)

func (r *v2ReachabilityReader) lockExisting() (*os.File, os.FileInfo, error) {
	if err := r.step(); err != nil {
		return nil, nil, err
	}
	dir, info, err := r.directory()
	if err != nil {
		return nil, nil, err
	}
	closeErr := r.closeFile(dir)
	if closeErr != nil {
		return nil, nil, errV2Unavailable
	}
	if err := r.step(); err != nil {
		return nil, nil, err
	}
	lock, err := openRecordFile(r.area, "checkpoint.lock")
	if err != nil {
		return nil, nil, errV2Unavailable
	}
	if err := r.step(); err != nil {
		_ = r.closeFile(lock)
		return nil, nil, err
	}
	li, err := lock.Stat()
	if err != nil || !regularOwned(li, 0) || !v2PhysicalSameDevice(info, li) {
		_ = r.closeFile(lock)
		return nil, nil, errV2Unavailable
	}
	if err := r.step(); err != nil {
		_ = r.closeFile(lock)
		return nil, nil, err
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		_ = r.closeFile(lock)
		return nil, nil, ErrLocked
	}
	r.root = info
	if err := r.verifyScope(lock); err != nil {
		_ = r.closeFile(lock)
		return nil, nil, err
	}
	return lock, info, nil
}

func (r *v2ReachabilityReader) verifyScope(lock *os.File) error {
	if err := r.step(); err != nil {
		return err
	}
	current, err := r.area.Stat(".")
	if err != nil || !current.IsDir() || current.Mode().Perm() != 0700 || !owned(current) || !os.SameFile(r.root, current) {
		return errV2Unavailable
	}
	if err := r.step(); err != nil {
		return err
	}
	opened, err := lock.Stat()
	if err != nil || !regularOwned(opened, 0) {
		return errV2Unavailable
	}
	if err := r.step(); err != nil {
		return err
	}
	named, err := r.area.Lstat("checkpoint.lock")
	if err != nil || !sameRecordFile(opened, named) {
		return errV2Unavailable
	}
	return nil
}

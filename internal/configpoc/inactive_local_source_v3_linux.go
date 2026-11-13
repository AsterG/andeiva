//go:build linux

package configpoc

import (
	"os"
	"syscall"
)

func openInactiveLocalSourceV3(area *os.Root) (*fileStore, error) {
	store := &fileStore{dir: area.Name(), limit: 1, scopedRoot: area}
	pinned, err := store.openScopedRoot()
	if err != nil {
		return nil, err
	}
	defer pinned.Close()
	lock, err := pinned.OpenFile("state.lock", os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	fail := func(e error) (*fileStore, error) { _ = lock.Close(); return nil, e }
	info, err := lock.Stat()
	if err != nil || !regularOwned(info, 0) {
		return fail(ErrStorage)
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return fail(ErrLocked)
	}
	store.lock = lock
	if err = store.load(); err != nil {
		return fail(err)
	}
	return store, nil
}

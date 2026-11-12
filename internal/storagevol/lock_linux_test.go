//go:build linux

package storagevol

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestInspectionLockIsReadOnlyAndExclusive(t *testing.T) {
	area, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	if err = area.WriteFile("preparation.lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := area.OpenFile("preparation.lock", preparationLockFlags(false), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	flags, err := unix.FcntlInt(first.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatal("inspection needs writable descriptor", flags, err)
	}
	if _, err = first.Write([]byte("forbidden")); !errors.Is(err, unix.EBADF) {
		t.Fatal("inspection descriptor accepted write", err)
	}
	if err = unix.Flock(int(first.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	second, err := area.OpenFile("preparation.lock", preparationLockFlags(false), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err = unix.Flock(int(second.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatal("inspection did not exclude competing handle", err)
	}
	if err = unix.Flock(int(first.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err = unix.Flock(int(second.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("lock was not reusable", err)
	}
	data, err := area.ReadFile("preparation.lock")
	if err != nil || len(data) != 0 {
		t.Fatal("lock contents changed", err)
	}
	if preparationLockFlags(true)&unix.O_ACCMODE != unix.O_RDWR {
		t.Fatal("preparation descriptor lost required write access")
	}
}

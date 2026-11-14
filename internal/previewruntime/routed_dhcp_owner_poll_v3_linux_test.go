//go:build linux

package previewruntime

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRoutedDHCPOwnerPollRetriesInterruptedLivePIDFD(t *testing.T) {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	for interrupts := 1; interrupts < 4; interrupts++ {
		calls := 0
		alive := routedDHCPOwnerPollAliveV3(int32(fd), func(fds []unix.PollFd, timeout int) (int, error) {
			calls++
			if timeout != 0 || len(fds) != 1 || fds[0].Fd != int32(fd) || fds[0].Events != unix.POLLIN || fds[0].Revents != 0 {
				t.Fatal("changed observation")
			}
			if calls <= interrupts {
				return -1, unix.EINTR
			}
			return unix.Poll(fds, timeout) // Positive requires a real live pidfd.
		})
		if !alive || calls != interrupts+1 {
			t.Fatal("interruption declared a live owner dead", interrupts, calls)
		}
	}
}

func TestRoutedDHCPOwnerPollFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		n      int
		err    error
		events int16
	}{
		"interruption_exhaustion": {-1, unix.EINTR, 0}, "badfd": {-1, unix.EBADF, 0}, "other_error": {-1, unix.EIO, 0},
		"exited": {1, nil, unix.POLLIN}, "hup": {1, nil, unix.POLLHUP}, "invalid": {1, nil, unix.POLLNVAL},
		"unexpected_count": {1, nil, 0}, "unexpected_events": {0, nil, unix.POLLIN},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			if routedDHCPOwnerPollAliveV3(42, func(fds []unix.PollFd, timeout int) (int, error) {
				calls++
				if timeout != 0 || calls > 4 {
					t.Fatal("unbounded or blocking retry")
				}
				fds[0].Revents = tc.events
				return tc.n, tc.err
			}) {
				t.Fatal("uncertainty accepted as liveness")
			}
			want := 1
			if tc.err == unix.EINTR {
				want = 4
			}
			if calls != want {
				t.Fatal("wrong retry count", calls)
			}
		})
	}
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "own-test-pidfd")
	if !routedDHCPOwnerPIDFDAliveV3(f, os.Getpid()) || routedDHCPOwnerPIDFDAliveV3(f, os.Getpid()+1) {
		t.Fatal("pidfd identity")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if routedDHCPOwnerPIDFDAliveV3(f, os.Getpid()) || routedDHCPOwnerPollAliveV3(-1, unix.Poll) {
		t.Fatal("closed/invalid descriptor alive")
	}
}

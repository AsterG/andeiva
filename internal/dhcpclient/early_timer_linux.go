//go:build linux

package dhcpclient

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

type earlyRenewalTimer interface {
	arm(int64) error
	wait() <-chan error
	close()
}

// Go's ordinary timer excludes suspend on Linux. An absolute BOOTTIME timer
// keeps dispatch and response budgets in the same clock domain as the lease.
type earlyBootTimer struct {
	file *os.File
	tick chan error
	stop chan struct{}
	done chan struct{}
}

func newEarlyBootTimer() (earlyRenewalTimer, error) {
	fd, err := unix.TimerfdCreate(unix.CLOCK_BOOTTIME, unix.TFD_CLOEXEC|unix.TFD_NONBLOCK)
	if err != nil {
		return nil, err
	}
	t := &earlyBootTimer{file: os.NewFile(uintptr(fd), "dhcp-renewal-timer"), tick: make(chan error, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(t.done)
		var count [8]byte
		for {
			_, err := io.ReadFull(t.file, count[:])
			select {
			case <-t.stop:
				return
			case t.tick <- err:
			}
			if err != nil {
				return
			}
		}
	}()
	return t, nil
}

func (t *earlyBootTimer) arm(deadline int64) error {
	if deadline <= 0 {
		return ErrUnavailable
	}
	spec := unix.ItimerSpec{Value: unix.NsecToTimespec(deadline)}
	return unix.TimerfdSettime(int(t.file.Fd()), unix.TFD_TIMER_ABSTIME, &spec, nil)
}

func (t *earlyBootTimer) wait() <-chan error { return t.tick }

func (t *earlyBootTimer) close() {
	close(t.stop)
	_ = t.file.Close() // NONBLOCK os.File polling is interrupted by Close.
	<-t.done
}

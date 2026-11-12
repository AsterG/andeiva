//go:build linux

package routedflow

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSocketErrorsAreStableAndNeverEmptySuccess(t *testing.T) {
	for _, tc := range []struct{ input, want error }{
		{unix.ENOENT, ErrUnavailable}, {unix.EPERM, ErrPermission}, {unix.EACCES, ErrPermission},
		{unix.ENOBUFS, ErrInterrupted}, {unix.EPROTONOSUPPORT, ErrUnavailable}, {unix.EIO, ErrTransport},
	} {
		if !errors.Is(socketError(tc.input), tc.want) {
			t.Fatal(tc)
		}
	}
	if socketError(nil) != nil {
		t.Fatal("successful syscall failed")
	}
}
func TestCancelledLinuxCallsDoNotOpenOrUseSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Collect(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	s := &netlinkSocket{fd: -1}
	if e := s.send(ctx, nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := s.receive(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e := s.wait(context.Background(), unix.POLLIN); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
}

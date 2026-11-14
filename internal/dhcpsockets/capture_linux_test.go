//go:build linux

package dhcpsockets

import (
	"context"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"testing"
	"time"
)

func TestCaptureMatchesRealKernelSocket(t *testing.T) {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	u := c.(*net.UDPConn)
	raw, err := u.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cookie uint64
	var inode uint64
	var observed error
	if err = raw.Control(func(fd uintptr) {
		cookie, observed = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		if observed != nil {
			return
		}
		var st unix.Stat_t
		observed = unix.Fstat(int(fd), &st)
		inode = st.Ino
	}); err != nil || observed != nil {
		t.Fatal(err, observed)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rows, err := CaptureIPv4UDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, s := range rows {
		if s.Cookie == cookie {
			found++
			if uint64(s.Inode) != inode || s.UID != uint32(os.Geteuid()) || s.Port != uint16(c.LocalAddr().(*net.UDPAddr).Port) || s.Address.String() != "127.0.0.1" || s.CreationCgroup == 0 {
				t.Fatalf("kernel identity mismatch: %+v", s)
			}
		}
	}
	if found != 1 {
		t.Fatalf("expected one real socket, got %d", found)
	}
}
func TestCaptureRejectsInvalidContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []context.Context{nil, ctx} {
		if _, err := CaptureIPv4UDP(c); err == nil {
			t.Fatal("invalid context accepted")
		}
	}
}

//go:build linux

package previewruntime

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func routedUnixPairV3(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	files := [2]*os.File{os.NewFile(uintptr(fds[0]), "routed-client"), os.NewFile(uintptr(fds[1]), "routed-helper")}
	var out [2]*net.UnixConn
	for i, file := range files {
		conn, e := net.FileConn(file)
		_ = file.Close()
		if e != nil {
			for _, c := range out {
				if c != nil {
					_ = c.Close()
				}
			}
			t.Fatal(e)
		}
		out[i] = conn.(*net.UnixConn)
		t.Cleanup(func() { _ = conn.Close() })
	}
	return out[0], out[1]
}
func TestRoutedInheritedV3RequiresKernelPeerIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	session, e := NewRoutedSessionV3(&routedTransportAuthorityV3{}, routedTransportReaderV3{})
	if e != nil {
		t.Fatal(e)
	}
	uid, gid, pid := uint32(os.Geteuid()), uint32(os.Getegid()), int32(os.Getpid())
	a, b := routedUnixPairV3(t)
	done := make(chan error, 1)
	go func() { done <- session.ServeInheritedRoutedV3(ctx, b, uid, gid, pid, strings.Repeat("a", 32)) }()
	client, e := ConnectInheritedRoutedV3(ctx, a, uid, gid, pid, strings.Repeat("a", 32), 22)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = client.Call(ctx, "observe", struct{}{}); e != nil {
		t.Fatal(e)
	}
	_ = client.Close()
	<-done
	for _, wrong := range []struct {
		uid, gid uint32
		pid      int32
	}{{uid + 1, gid, pid}, {uid, gid + 1, pid}, {uid, gid, pid + 1}, {uid, gid, 1}} {
		clientSide, _ := routedUnixPairV3(t)
		if c, e := ConnectInheritedRoutedV3(ctx, clientSide, wrong.uid, wrong.gid, wrong.pid, strings.Repeat("a", 32), 22); e == nil {
			_ = c.Close()
			t.Fatal("forged peer accepted")
		}
		_, serverSide := routedUnixPairV3(t)
		if e := session.ServeInheritedRoutedV3(ctx, serverSide, wrong.uid, wrong.gid, wrong.pid, strings.Repeat("a", 32)); e == nil {
			t.Fatal("forged controller accepted")
		}
	}
}

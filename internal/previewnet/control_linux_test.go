package previewnet

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s")
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = l.Close() })
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	s, e := l.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	if c.SetDeadline(time.Now().Add(time.Second)) != nil || s.SetDeadline(time.Now().Add(time.Second)) != nil {
		t.Fatal("deadline")
	}
	return c, s
}

func TestControlUsesKernelPeerCredentials(t *testing.T) {
	c, s := unixPair(t)
	want := os.Geteuid() == 0
	if rootPeer(c) != want || rootPeer(s) != want {
		t.Fatal("peer credential mismatch")
	}
}

func TestControlFrameRejectsOversizeUnknownFieldsAndExtraJSON(t *testing.T) {
	for _, frame := range []string{strings.Repeat("x", 4096) + "\n", `{"operation":"status","path":"/proc/1/ns/net"}` + "\n", `{"operation":"status"}{}` + "\n"} {
		c, s := unixPair(t)
		if _, e := c.Write([]byte(frame)); e != nil {
			t.Fatal(e)
		}
		var r ControlRequest
		if readFrame(s, &r) == nil {
			t.Fatal("unsafe frame accepted")
		}
	}
	c, s := unixPair(t)
	if _, e := c.Write([]byte("{\"operation\":\"probe\",\"protocol\":\"udp\",\"port\":18080}\n")); e != nil {
		t.Fatal(e)
	}
	var r ControlRequest
	if readFrame(s, &r) != nil || r.Validate() != nil {
		t.Fatal("valid bounded request rejected")
	}
}

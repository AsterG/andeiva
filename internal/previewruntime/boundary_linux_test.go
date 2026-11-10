//go:build linux

package previewruntime

import (
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestIdentityComparisonDoesNotWrap(t *testing.T) {
	for _, test := range []struct {
		actual   int
		expected uint32
		match    bool
	}{
		{-1, math.MaxUint32, false}, {-2, math.MaxUint32 - 1, false}, {1001, 1001, true}, {1002, 1001, false}, {65534, 65534, true},
	} {
		if got := matchesIdentity(test.actual, test.expected); got != test.match {
			t.Fatalf("matchesIdentity(%d,%d)=%v", test.actual, test.expected, got)
		}
	}
	if strconv.IntSize == 64 {
		overflow := int64(1)<<32 | 1001
		if matchesIdentity(int(overflow), 1001) {
			t.Fatal("oversized identity wrapped into authorized UID")
		}
	}
}

func TestListenerRejectsUnboundDevice(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c := testConfig()
	c.ListenAddress = listener.Addr().String()
	c.Interface = "lo"
	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr, validation error
	var index int
	if err = raw.Control(func(fd uintptr) {
		index, optionErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, soBindToIfindex)
		validation = validateListener(int(fd), c)
	}); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil || index != 0 {
		t.Fatalf("expected available unbound-device socket option: %d %v", index, optionErr)
	}
	if validation == nil {
		t.Fatal("address alone authorized an unbound management listener")
	}
}

func TestDirectorySyncRejectsSymlink(t *testing.T) {
	parent := privateDir(t)
	actual := filepath.Join(parent, "actual")
	if os.Mkdir(actual, 0700) != nil {
		t.Fatal("mkdir")
	}
	if syncDirectory(actual) != nil {
		t.Fatal("directory sync failed")
	}
	alias := filepath.Join(parent, "alias")
	if os.Symlink(actual, alias) != nil {
		t.Fatal("symlink")
	}
	if syncDirectory(alias) == nil {
		t.Fatal("symlink directory was followed")
	}
}

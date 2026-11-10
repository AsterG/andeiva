//go:build linux

package previewruntime

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
)

// SO_BINDTOIFINDEX is the Linux socket ABI for the device selected by
// SO_BINDTODEVICE. The frozen syscall package omits it on amd64 and arm64.
const soBindToIfindex = 62

func validateListener(fd int, c Config) error {
	addr, e := syscall.Getsockname(fd)
	a, ok := addr.(*syscall.SockaddrInet4)
	expected, pe := netip.ParseAddrPort(c.ListenAddress)
	if e != nil || !ok || pe != nil || netip.AddrFrom4(a.Addr) != expected.Addr() || a.Port != int(expected.Port()) {
		return ErrIdentity
	}
	iface, e := net.InterfaceByName(c.Interface)
	if e != nil {
		return ErrIdentity
	}
	boundIndex, e := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, soBindToIfindex)
	if e != nil || boundIndex <= 0 || boundIndex != iface.Index {
		return ErrIdentity
	}
	kind, e := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if e != nil || kind != syscall.SOCK_STREAM {
		return ErrIdentity
	}
	accepting, e := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
	if e != nil || accepting != 1 {
		return ErrIdentity
	}
	return nil
}
func inheritedListener(c Config) (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return nil, ErrIdentity
	}
	if validateListener(3, c) != nil {
		return nil, ErrIdentity
	}
	iface, e := net.InterfaceByName(c.Interface)
	if e != nil {
		return nil, ErrIdentity
	}
	addresses, e := iface.Addrs()
	if e != nil {
		return nil, ErrIdentity
	}
	expected, _ := netip.ParseAddrPort(c.ListenAddress)
	found := false
	for _, a := range addresses {
		p, e := netip.ParsePrefix(a.String())
		if e == nil && p.Addr() == expected.Addr() {
			found = true
		}
	}
	if !found {
		return nil, ErrIdentity
	}
	f := os.NewFile(3, "management-listener")
	if f == nil {
		return nil, ErrIdentity
	}
	l, e := net.FileListener(f)
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		if l != nil {
			_ = l.Close() // A failed descriptor handoff cannot leave a listener active.
		}
		return nil, ErrIdentity
	}
	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	_ = os.Unsetenv("LISTEN_FDNAMES")
	return l, nil
}

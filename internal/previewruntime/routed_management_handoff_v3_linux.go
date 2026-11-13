//go:build linux

package previewruntime

import (
	"net"
	"net/netip"
	"os"

	"golang.org/x/sys/unix"
)

func routedManagementAddressPresentV3(c Config) bool {
	if c.Validate() != nil {
		return false
	}
	iface, err := net.InterfaceByName(c.Interface)
	if err != nil {
		return false
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return false
	}
	expected, err := netip.ParseAddrPort(c.ListenAddress)
	if err != nil {
		return false
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr() == expected.Addr() {
			return true
		}
	}
	return false
}

// The root activation consumer owns file. Duplicate it without consuming or
// inspecting activation environment again; FD order no longer identifies it.
func duplicateRoutedManagementV3(c Config, file *os.File) (*os.File, error) {
	if validateRoutedManagementV3(file, c) != nil || !routedManagementAddressPresentV3(c) {
		return nil, ErrIdentity
	}
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil || fd < 0 {
		return nil, ErrIdentity
	}
	copy := os.NewFile(uintptr(fd), "routed-management")
	if validateRoutedManagementV3(copy, c) != nil || !routedManagementAddressPresentV3(c) {
		_ = copy.Close()
		return nil, ErrIdentity
	}
	return copy, nil
}

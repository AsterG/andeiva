//go:build linux

package previewruntime

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const routedDHCPDelegatedCapsV1 = 1<<unix.CAP_NET_BIND_SERVICE | 1<<unix.CAP_NET_RAW

// Keep DHCP privileges unavailable to the supervisor's own operations. The
// packaged ceiling may retain them for the fixed DHCP role launch. Lowering the
// inheritable set also clears these bits from the ambient set.
func dropRoutedSupervisorDHCPNetworkCapsV1() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var expected [2]unix.CapUserData
	if err := unix.Capget(&hdr, &expected[0]); err != nil {
		return ErrIdentity
	}
	if (expected[0].Effective|expected[0].Inheritable)&routedDHCPDelegatedCapsV1 == 0 {
		return nil
	}
	expected[0].Effective &^= routedDHCPDelegatedCapsV1
	expected[0].Inheritable &^= routedDHCPDelegatedCapsV1
	// A thread-local reduction leaves other Go threads privileged. The shipped
	// binary is built without cgo. The kernel receives a fixed v3 capset buffer.
	_, _, errno := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&expected[0])), 0) // #nosec G103 -- fixed kernel ABI buffers
	if errno != 0 {
		return ErrIdentity
	}
	var actual [2]unix.CapUserData
	if err := unix.Capget(&hdr, &actual[0]); err != nil || actual != expected {
		return ErrIdentity
	}
	return nil
}

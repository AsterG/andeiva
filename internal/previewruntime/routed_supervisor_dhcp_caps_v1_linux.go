//go:build linux

package previewruntime

import (
	"os"
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

const routedDHCPRoleProfileEnvV1 = "ANDEIVA_PREVIEW_DHCP_ROLE_PROFILE"

const routedSupervisorDHCPBaseCapsV1 = 1<<unix.CAP_SYS_ADMIN | 1<<unix.CAP_SYS_CHROOT |
	1<<unix.CAP_NET_ADMIN | 1<<unix.CAP_SETUID | 1<<unix.CAP_SETGID | 1<<unix.CAP_SETPCAP |
	1<<unix.CAP_DAC_READ_SEARCH | 1<<unix.CAP_KILL | 1<<unix.CAP_CHOWN

const routedDHCPNoRootLockedV1 = 0x3 // SECBIT_NOROOT and SECBIT_NOROOT_LOCKED.

func configureRoutedSupervisorDHCPExecutionV1() error {
	switch os.Getenv(routedDHCPRoleProfileEnvV1) {
	case "":
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var caps [2]unix.CapUserData
		if err := unix.Capget(&hdr, &caps[0]); err != nil || caps[0].Permitted&routedDHCPDelegatedCapsV1 != 0 {
			return ErrIdentity
		}
		return nil
	case "1":
		scope, err := routedDHCPOwnerReadV3("/proc/self/cgroup", 4096)
		if err != nil || string(scope) != "0::"+routedSupervisorCgroupV3+"\n" {
			return ErrIdentity
		}
		if err := dropRoutedSupervisorDHCPNetworkCapsV1(); err != nil {
			return err
		}
		return restrictRoutedDHCPRootExecV1()
	default:
		return ErrIdentity
	}
}

// An opted-in supervisor has dormant permitted DHCP capabilities. Turn off
// root's implicit exec elevation and carry only the ordinary unit capabilities
// across regular helper execs. The fixed DHCP launches opt into the extra pair.
func restrictRoutedDHCPRootExecV1() error {
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	secure, secureErr := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	if err != nil || nnp != 1 || secureErr != nil || secure < 0 {
		return ErrIdentity
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if unix.Capget(&hdr, &caps[0]) != nil || caps[1] != (unix.CapUserData{}) ||
		caps[0].Effective != routedSupervisorDHCPBaseCapsV1 ||
		caps[0].Permitted != routedSupervisorDHCPBaseCapsV1|routedDHCPDelegatedCapsV1 ||
		caps[0].Inheritable&^routedSupervisorDHCPBaseCapsV1 != 0 {
		return ErrIdentity
	}
	caps[0].Inheritable = routedSupervisorDHCPBaseCapsV1
	_, _, errno := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&caps[0])), 0) // #nosec G103 -- fixed kernel ABI buffers
	if errno != 0 {
		return ErrIdentity
	}
	_, _, errno = syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, unix.PR_SET_SECUREBITS, uintptr(secure|routedDHCPNoRootLockedV1), 0, 0, 0, 0)
	if errno != 0 {
		return ErrIdentity
	}
	for index := uintptr(0); index < 32; index++ {
		if routedSupervisorDHCPBaseCapsV1&(1<<index) == 0 {
			continue
		}
		_, _, errno = syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, index, 0, 0, 0)
		if errno != 0 {
			return ErrIdentity
		}
	}
	return nil
}

func setRoutedDHCPChildNetworkCapsV1(attr *syscall.SysProcAttr) error {
	switch os.Getenv(routedDHCPRoleProfileEnvV1) {
	case "":
		return nil
	case "1":
		secure, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
		if attr == nil || err != nil || secure&routedDHCPNoRootLockedV1 != routedDHCPNoRootLockedV1 {
			return ErrIdentity
		}
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var caps [2]unix.CapUserData
		if unix.Capget(&hdr, &caps[0]) != nil || caps[1] != (unix.CapUserData{}) ||
			caps[0].Effective != routedSupervisorDHCPBaseCapsV1 ||
			caps[0].Inheritable != routedSupervisorDHCPBaseCapsV1 ||
			caps[0].Permitted != routedSupervisorDHCPBaseCapsV1|routedDHCPDelegatedCapsV1 {
			return ErrIdentity
		}
		attr.AmbientCaps = []uintptr{unix.CAP_NET_BIND_SERVICE, unix.CAP_NET_RAW}
		return nil
	default:
		return ErrIdentity
	}
}

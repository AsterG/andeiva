//go:build linux

package previewruntime

import (
	"golang.org/x/sys/unix"
	"os"
	"unsafe"
)

// The role must retain its OS-thread pin from before this call until exit.
// The inherited exec attribute can be cleared by setuid; rearm and read it
// back only after authenticating the root parent and final dropped identity.
func armMigrationParentDeathV3(parentPID int) error {
	if parentPID <= 1 || os.Getppid() != parentPID || unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0) != nil {
		return ErrIdentity
	}
	signal, err := migrationParentDeathSignalV3()
	if err != nil || signal != int32(unix.SIGKILL) || os.Getppid() != parentPID {
		return ErrIdentity
	}
	return nil
}
func migrationParentDeathSignalV3() (int32, error) {
	var signal int32
	// #nosec G103 -- Fixed Linux PR_GET_PDEATHSIG writes only this typed stack int32; no caller pointer or arbitrary memory access.
	_, _, errno := unix.Syscall6(unix.SYS_PRCTL, uintptr(unix.PR_GET_PDEATHSIG), uintptr(unsafe.Pointer(&signal)), 0, 0, 0, 0)
	if errno != 0 {
		return 0, ErrIdentity
	}
	return signal, nil
}

//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const routedDHCPPackageDirectoryV1 = "dhcp-server"
const routedDHCPPackageLeasesV1 = "leases"

// PrepareRoutedDHCPPackageStateV1 is invoked explicitly by offline provisioning.
// It reserves operational state without enabling the unit or seeding leases.
func PrepareRoutedDHCPPackageStateV1(ctx context.Context, c Config) error {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || c.Validate() != nil {
		return ErrIdentity
	}
	if safeParents(routedRetirementDirectoryV3+"/"+routedDHCPPackageDirectoryV1) != nil {
		return ErrIdentity
	}
	packageRoot, err := os.OpenRoot(routedRetirementDirectoryV3)
	if err != nil {
		return ErrStorage
	}
	defer packageRoot.Close()
	uid, gid, err := routedDHCPServerAccountV1()
	if err != nil {
		return err
	}
	return prepareRoutedDHCPStateUnderV1(packageRoot, uid, gid)
}

func prepareRoutedDHCPStateUnderV1(packageRoot *os.Root, uid, gid uint32) error {
	if packageRoot == nil || uid == 0 || gid == 0 {
		return ErrIdentity
	}
	parent, err := packageRoot.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrStorage
	}
	defer parent.Close()
	if !routedDHCPPackageDirectoryOwnedV1(parent, 0, 0) {
		return ErrIdentity
	}
	if err := packageRoot.Mkdir(routedDHCPPackageDirectoryV1, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return ErrStorage
	}
	state, err := packageRoot.OpenFile(routedDHCPPackageDirectoryV1, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrStorage
	}
	defer state.Close()
	if !routedDHCPPackageDirectoryOwnedV1(state, 0, 0) {
		return ErrIdentity
	}
	if err := unix.Flock(int(state.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return ErrUnavailable
	}
	if err := unix.Mkdirat(int(state.Fd()), routedDHCPPackageLeasesV1, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return ErrStorage
	}
	fd, err := unix.Openat(int(state.Fd()), routedDHCPPackageLeasesV1, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrStorage
	}
	leases := os.NewFile(uintptr(fd), "kea-operational-leases")
	defer leases.Close()
	if !routedDHCPPackageDirectoryOwnedV1(leases, uid, gid) {
		// A crash between mkdir and ownership assignment can leave the empty
		// directory root-owned. Never take over an existing nonempty store.
		if !routedDHCPPackageDirectoryOwnedV1(leases, 0, 0) {
			return ErrIdentity
		}
		entries, err := leases.Readdirnames(1)
		if len(entries) != 0 || err != io.EOF {
			return ErrIdentity
		}
		if leases.Chown(int(uid), int(gid)) != nil || !routedDHCPPackageDirectoryOwnedV1(leases, uid, gid) {
			return ErrStorage
		}
	}
	return errors.Join(leases.Sync(), state.Sync(), parent.Sync())
}

func routedDHCPPackageDirectoryOwnedV1(file *os.File, uid, gid uint32) bool {
	var stat unix.Stat_t
	return unix.Fstat(int(file.Fd()), &stat) == nil && stat.Mode == unix.S_IFDIR|0700 &&
		stat.Uid == uid && stat.Gid == gid && fenceNoACLV3(file, true)
}

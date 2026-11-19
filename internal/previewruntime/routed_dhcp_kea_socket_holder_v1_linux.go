//go:build linux

package previewruntime

import (
	"errors"
	"io"
	"math"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type routedKeaEngineIdentityV1 struct {
	pid, parent int
	start       uint64
	namespace   uint64
	uid, gid    uint32
}

const routedKeaEngineNetworkCapsV1 = 1<<unix.CAP_NET_BIND_SERVICE | 1<<unix.CAP_NET_RAW

// Only the fixed Kea launcher calls this in the pinned gateway. Filesystem
// credentials allow Linux to check the dedicated engine's actual descriptors
// without granting CAP_SYS_PTRACE or minting packet ownership from a UID.
func readRoutedKeaEngineSocketHoldersV1(process *os.File, identity routedKeaEngineIdentityV1) ([]uint64, error) {
	if identity.pid <= 1 || identity.parent <= 1 || identity.start == 0 || identity.namespace == 0 ||
		identity.uid == 0 || identity.gid == 0 || identity.uid > math.MaxInt32 || identity.gid > math.MaxInt32 ||
		os.Getuid() != 0 || os.Geteuid() != 0 || !routedDHCPOwnerPIDFDAliveV3(process, identity.pid) {
		return nil, ErrIdentity
	}
	ticks, parent, err := routedDHCPOwnerProcessV3(identity.pid)
	if err != nil || ticks != identity.start || parent != identity.parent {
		return nil, ErrIdentity
	}
	type observation struct {
		inodes []uint64
		err    error
	}
	// Keep this existing caller thread outside the credential change. No
	// subprocess is launched from the thread that receives the filesystem IDs.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	observed := make(chan observation, 1)
	go func() {
		runtime.LockOSThread()
		if unix.Gettid() == os.Getpid() {
			defer runtime.UnlockOSThread()
			private := make(chan observation, 1)
			go func() {
				runtime.LockOSThread()
				inodes, err := readRoutedKeaEngineFDsV1(identity)
				private <- observation{inodes, err}
			}()
			observed <- <-private
			return
		}
		inodes, err := readRoutedKeaEngineFDsV1(identity)
		observed <- observation{inodes, err}
	}()
	found := <-observed
	ticks, parent, err = routedDHCPOwnerProcessV3(identity.pid)
	if found.err != nil || err != nil || ticks != identity.start || parent != identity.parent ||
		!routedDHCPOwnerPIDFDAliveV3(process, identity.pid) {
		return nil, errors.Join(ErrIdentity, found.err)
	}
	return found.inodes, nil
}

// Only call on a dedicated locked thread that will be retired. Read exactly
// the pinned engine's PID directory and bound concurrent descriptor churn.
func readRoutedKeaEngineFDsV1(identity routedKeaEngineIdentityV1) (_ []uint64, result error) {
	if unix.Gettid() == os.Getpid() || identity.pid <= 1 || identity.pid > math.MaxInt32 {
		return nil, ErrIdentity
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if unix.Capget(&hdr, &caps[0]) != nil || caps[0].Effective&routedKeaEngineNetworkCapsV1 != routedKeaEngineNetworkCapsV1 ||
		(caps[0].Effective|caps[0].Permitted)&(1<<unix.CAP_SYS_PTRACE) != 0 {
		return nil, ErrIdentity
	}
	beforeUID, err := unix.SetfsuidRetUid(-1)
	beforeGID, other := unix.SetfsgidRetGid(-1)
	if err != nil || other != nil || beforeUID != 0 || beforeGID != 0 {
		return nil, ErrIdentity
	}
	defer func() {
		_, uerr := unix.SetfsuidRetUid(beforeUID)
		_, gerr := unix.SetfsgidRetGid(beforeGID)
		actualUID, ucheck := unix.SetfsuidRetUid(-1)
		actualGID, gcheck := unix.SetfsgidRetGid(-1)
		if uerr != nil || gerr != nil || ucheck != nil || gcheck != nil || actualUID != beforeUID || actualGID != beforeGID {
			result = errors.Join(result, ErrIdentity)
		}
	}()
	_, gerr := unix.SetfsgidRetGid(int(identity.gid))
	_, uerr := unix.SetfsuidRetUid(int(identity.uid))
	actualUID, ucheck := unix.SetfsuidRetUid(-1)
	actualGID, gcheck := unix.SetfsgidRetGid(-1)
	if gerr != nil || uerr != nil || ucheck != nil || gcheck != nil || actualUID != int(identity.uid) || actualGID != int(identity.gid) {
		return nil, ErrIdentity
	}
	proc, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer proc.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(proc.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, ErrIdentity
	}
	pid := strconv.Itoa(identity.pid)
	path := "/proc/" + pid
	ns, err := namespaceID(path + "/ns/net")
	profile, profileErr := routedDHCPOwnerReadV3(path+"/attr/current", 4096)
	if err != nil || ns != identity.namespace || profileErr != nil || strings.TrimSpace(string(profile)) != "kea-dhcp4 (enforce)" {
		return nil, ErrIdentity
	}
	fd, err := unix.Openat(int(proc.Fd()), pid+"/fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fds := os.NewFile(uintptr(fd), "kea-engine-descriptors")
	defer fds.Close()
	entries, err := fds.ReadDir(257)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > 256 {
		return nil, ErrUnavailable
	}
	var inodes []uint64
	var link [128]byte
	for _, entry := range entries {
		length, err := unix.Readlinkat(int(fds.Fd()), entry.Name(), link[:])
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		number, socket := strings.CutPrefix(string(link[:length]), "socket:[")
		if !socket {
			continue
		}
		inode, err := strconv.ParseUint(strings.TrimSuffix(number, "]"), 10, 64)
		if length == len(link) || !strings.HasSuffix(number, "]") || err != nil || inode == 0 {
			return nil, ErrIdentity
		}
		inodes = append(inodes, inode)
	}
	if len(inodes) == 0 {
		return nil, ErrUnavailable
	}
	slices.Sort(inodes)
	return slices.Compact(inodes), nil
}

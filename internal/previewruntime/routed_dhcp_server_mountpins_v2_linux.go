//go:build linux

package previewruntime

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Fixed, ordered identities extend the sealed root-role bootstrap, not the API.
type routedDHCPServerMountWireV2 struct {
	Role   string `json:"role"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type routedDHCPServerMountPinsV2 struct {
	configuration, leases *os.File
}

func routedDHCPServerMountAttributesV2(readonly bool) unix.MountAttr {
	a := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC}
	if readonly {
		a.Attr_set |= unix.MOUNT_ATTR_RDONLY
	} else {
		a.Attr_clr = unix.MOUNT_ATTR_RDONLY
	}
	return a
}

func routedDHCPServerMountFlagsV2(flags int64, readonly bool) bool {
	required := int64(unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
	return flags&required == required && (flags&unix.ST_RDONLY != 0) == readonly
}

func (p *routedDHCPServerMountPinsV2) closeV2() error {
	if p == nil {
		return nil
	}
	var result error
	for _, slot := range []**os.File{&p.configuration, &p.leases} {
		if *slot != nil {
			result = errors.Join(result, (*slot).Close())
			*slot = nil
		}
	}
	return result
}

// Source descriptors remain borrowed. Clone while their mounts still belong
// to the caller's namespace; never resolve their path in the isolated child.
func prepareRoutedDHCPServerMountPinsV2(configuration, leases *os.File) (pins *routedDHCPServerMountPinsV2, wire []routedDHCPServerMountWireV2, result error) {
	pins = &routedDHCPServerMountPinsV2{}
	defer func() {
		if result != nil {
			if closeErr := pins.closeV2(); closeErr != nil {
				result = errors.Join(result, closeErr)
			}
			pins, wire = nil, nil
		}
	}()
	for _, item := range []struct {
		role     string
		source   *os.File
		target   **os.File
		readonly bool
	}{
		{"configuration", configuration, &pins.configuration, true},
		{"leases", leases, &pins.leases, false},
	} {
		if item.source == nil {
			return pins, nil, ErrIdentity
		}
		var st unix.Stat_t
		kind := uint32(unix.S_IFDIR)
		if item.readonly {
			kind = unix.S_IFREG
		}
		if unix.Fstat(int(item.source.Fd()), &st) != nil || st.Mode&unix.S_IFMT != kind || st.Dev == 0 || st.Ino == 0 {
			return pins, nil, ErrIdentity
		}
		fd, err := unix.OpenTree(int(item.source.Fd()), "", unix.OPEN_TREE_CLONE|unix.AT_EMPTY_PATH|unix.O_CLOEXEC)
		if err != nil {
			return pins, nil, ErrUnavailable
		}
		*item.target = os.NewFile(uintptr(fd), "detached-dhcp-server-mount")
		a := routedDHCPServerMountAttributesV2(item.readonly)
		if unix.MountSetattr(fd, "", unix.AT_EMPTY_PATH, &a) != nil || validateRoutedDHCPServerMountPinV2(fd, st, item.readonly) != nil {
			return pins, nil, ErrUnavailable
		}
		wire = append(wire, routedDHCPServerMountWireV2{item.role, uint64(st.Dev), st.Ino})
	}
	return pins, wire, nil
}

func validateRoutedDHCPServerMountPinV2(fd int, source unix.Stat_t, readonly bool) error {
	var st unix.Stat_t
	var fs unix.Statfs_t
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_PATH == 0 || unix.Fstat(fd, &st) != nil || st.Dev != source.Dev || st.Ino != source.Ino || st.Mode != source.Mode || st.Uid != source.Uid || st.Gid != source.Gid || unix.Fstatfs(fd, &fs) != nil || !routedDHCPServerMountFlagsV2(fs.Flags, readonly) {
		return ErrIdentity
	}
	return nil
}

func attachRoutedDHCPServerMountV2(tree **os.File, source *os.File, target string, readonly bool) error {
	if tree == nil || *tree == nil || source == nil || readonly && target != routedDHCPServerConfigV1 || !readonly && target != "/var/lib/kea" {
		return ErrIdentity
	}
	var st unix.Stat_t
	if unix.Fstat(int(source.Fd()), &st) != nil || validateRoutedDHCPServerMountPinV2(int((*tree).Fd()), st, readonly) != nil {
		return ErrIdentity
	}
	if err := unix.MoveMount(int((*tree).Fd()), "", unix.AT_FDCWD, target, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return routedDHCPServerMountFailureV1("move_mount", err, ErrUnavailable)
	}
	var after unix.Stat_t
	var fs unix.Statfs_t
	if unix.Stat(target, &after) != nil || after.Dev != st.Dev || after.Ino != st.Ino || unix.Statfs(target, &fs) != nil || !routedDHCPServerMountFlagsV2(fs.Flags, readonly) {
		return ErrIdentity
	}
	err := (*tree).Close()
	*tree = nil
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

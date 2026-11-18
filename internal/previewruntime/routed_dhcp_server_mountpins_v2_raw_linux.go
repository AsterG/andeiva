//go:build linux

package previewruntime

import "golang.org/x/sys/unix"

type routedDHCPServerRawFDV2 struct {
	stat             unix.Stat_t
	fs               unix.Statfs_t
	flags, namespace int
}

func routedDHCPServerMountWireValidV2(pins []routedDHCPServerMountWireV2) bool {
	return len(pins) == 2 && pins[0].Role == "configuration" && pins[1].Role == "leases" && pins[0].Device != 0 && pins[0].Inode != 0 && pins[1].Device != 0 && pins[1].Inode != 0
}

// Capture the complete inherited contract before os.NewFile can create poller
// descriptors. Missing slots must never be supplied by later runtime activity.
func captureRoutedDHCPServerRawFDsV2(b routedDHCPServerBootstrapV2) error {
	if !routedDHCPServerMountWireValidV2(b.MountPins) || len(b.ServiceCgroups) < 1 || len(b.ServiceCgroups) > 2 {
		return ErrIdentity
	}
	var raw [14]routedDHCPServerRawFDV2
	slots := []struct {
		fd     int
		target *routedDHCPServerRawFDV2
	}{
		{3, &raw[3]}, {4, &raw[4]}, {5, &raw[5]}, {6, &raw[6]}, {7, &raw[7]},
		{8, &raw[8]}, {9, &raw[9]}, {10, &raw[10]}, {11, &raw[11]}, {12, &raw[12]},
	}
	if len(b.ServiceCgroups) == 2 {
		slots = append(slots, struct {
			fd     int
			target *routedDHCPServerRawFDV2
		}{13, &raw[13]})
	}
	for _, slot := range slots {
		fd, r := slot.fd, slot.target
		var err error
		if unix.Fstat(fd, &r.stat) != nil || unix.Fstatfs(fd, &r.fs) != nil {
			return ErrIdentity
		}
		r.flags, err = unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil {
			return ErrIdentity
		}
		if fd <= 5 {
			r.namespace, err = unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
			if err != nil {
				return ErrIdentity
			}
		}
	}
	if err := checkRoutedDHCPServerRawFDEndV2(len(b.ServiceCgroups)); err != nil {
		return err
	}
	return validateRoutedDHCPServerRawFDsV2(b, raw)
}

func checkRoutedDHCPServerRawFDEndV2(cgroupPins int) error {
	// ExtraFiles are contiguous starting at FD3. A close-on-exec descriptor
	// could not survive this role's exec. Go can open its own cpu.max with
	// O_CLOEXEC before role entry, including at the first slot past the pins.
	flags, err := unix.FcntlInt(uintptr(12+cgroupPins), unix.F_GETFD, 0)
	if err == unix.EBADF || (err == nil && flags == unix.FD_CLOEXEC) {
		return nil
	}
	return ErrIdentity
}

func validateRoutedDHCPServerRawFDsV2(b routedDHCPServerBootstrapV2, raw [14]routedDHCPServerRawFDV2) error {
	if len(b.MountPins) != 2 || !routedDHCPServerMountWireValidV2(b.MountPins) || len(b.ServiceCgroups) < 1 || len(b.ServiceCgroups) > 2 {
		return ErrIdentity
	}
	if len(b.ServiceCgroups) == 1 && raw[13] != (routedDHCPServerRawFDV2{}) {
		return ErrIdentity
	}
	for _, want := range []struct {
		actual routedDHCPServerRawFDV2
		kind   int
		inode  uint64
	}{{raw[3], unix.CLONE_NEWNET, b.Metadata.GatewayNamespace}, {raw[4], unix.CLONE_NEWNET, b.Metadata.HostNamespace}, {raw[5], unix.CLONE_NEWNS, b.HostMountNamespace}} {
		r := want.actual
		if r.fs.Type != unix.NSFS_MAGIC || r.namespace != want.kind || r.stat.Ino != want.inode || want.inode == 0 {
			return ErrIdentity
		}
	}
	config, leases := raw[6], raw[7]
	if config.stat.Mode != unix.S_IFREG|0440 || config.stat.Uid != 0 || config.stat.Nlink != 1 || config.stat.Size <= 0 || config.flags&unix.O_ACCMODE != unix.O_RDONLY || config.flags&unix.O_PATH != 0 || leases.stat.Mode != unix.S_IFDIR|0700 || leases.stat.Uid == 0 || leases.stat.Gid == 0 || leases.flags&unix.O_ACCMODE != unix.O_RDONLY || leases.flags&unix.O_PATH != 0 {
		return ErrIdentity
	}
	if raw[8].stat.Mode != unix.S_IFREG|0400 || raw[8].stat.Uid != 0 || raw[9].stat.Mode&unix.S_IFMT != unix.S_IFIFO || raw[9].flags&unix.O_ACCMODE != unix.O_RDONLY || raw[9].flags&unix.O_PATH != 0 {
		return ErrIdentity
	}
	for _, item := range []struct {
		source, tree routedDHCPServerRawFDV2
		wire         routedDHCPServerMountWireV2
		readonly     bool
	}{
		{config, raw[10], b.MountPins[0], true}, {leases, raw[11], b.MountPins[1], false},
	} {
		source, tree, wire := item.source, item.tree, item.wire
		if uint64(source.stat.Dev) != wire.Device || source.stat.Ino != wire.Inode || tree.stat.Dev != source.stat.Dev || tree.stat.Ino != source.stat.Ino || tree.stat.Mode != source.stat.Mode || tree.stat.Uid != source.stat.Uid || tree.stat.Gid != source.stat.Gid || tree.flags&unix.O_PATH == 0 || !routedDHCPServerMountFlagsV2(tree.fs.Flags, item.readonly) {
			return ErrIdentity
		}
	}
	if !routedDHCPServerRawCgroupV2(raw[12], b.ServiceCgroups[0]) || len(b.ServiceCgroups) == 2 && !routedDHCPServerRawCgroupV2(raw[13], b.ServiceCgroups[1]) {
		return ErrIdentity
	}
	return nil
}

func routedDHCPServerRawCgroupV2(r routedDHCPServerRawFDV2, pin routedDHCPServerCgroupWireV1) bool {
	return r.stat.Mode&unix.S_IFMT == unix.S_IFDIR && r.stat.Uid == 0 && r.stat.Mode&0022 == 0 && r.fs.Type == unix.CGROUP2_SUPER_MAGIC && r.flags&unix.O_ACCMODE == unix.O_RDONLY && r.flags&unix.O_PATH == 0 && uint64(r.stat.Dev) == pin.Device && r.stat.Ino == pin.Inode
}

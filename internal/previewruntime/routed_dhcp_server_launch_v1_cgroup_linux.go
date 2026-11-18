//go:build linux

package previewruntime

import (
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Root supplies exact, retained readonly pins for the complete enabled service
// set. These are borrowed capabilities, never administrative configuration.
type RoutedDHCPServerCgroupPinV1 struct {
	Role      string
	Name      string
	Identity  RoutedDHCPServiceCgroupIdentityV1
	Directory *os.File
}

func routedDHCPServerCgroupNameV1(role, incarnation string) (string, error) {
	if !ValidRun(incarnation) {
		return "", ErrIdentity
	}
	switch role {
	case "wan":
		return "dhcp-" + incarnation, nil
	case "lan":
		return "dhcp-server-" + incarnation, nil
	default:
		return "", ErrIdentity
	}
}

func routedDHCPServerCgroupPinNameV1(pin RoutedDHCPServerCgroupPinV1) bool {
	var prefix string
	switch pin.Role {
	case "wan":
		prefix = "dhcp-"
	case "lan":
		prefix = "dhcp-server-"
	default:
		return false
	}
	return len(pin.Name) == len(prefix)+32 && pin.Name[:len(prefix)] == prefix && ValidRun(pin.Name[len(prefix):]) && pin.Identity.Device != 0 && pin.Identity.Inode != 0
}

// Check the exact topology using metadata read from retained kernel objects.
// lookup must not resolve symlinks; production uses fstatat(AT_SYMLINK_NOFOLLOW).
func routedDHCPServerExactChildrenV1(names []string, pins []RoutedDHCPServerCgroupPinV1, parent RoutedDHCPServiceCgroupIdentityV1, lookup func(string) (RoutedDHCPServiceCgroupIdentityV1, error)) error {
	if len(pins) > 2 || len(names) != len(pins) || parent.Device == 0 || parent.Inode == 0 || lookup == nil {
		return ErrIdentity
	}
	roles, expected := map[string]bool{}, map[string]RoutedDHCPServiceCgroupIdentityV1{}
	for _, pin := range pins {
		if !routedDHCPServerCgroupPinNameV1(pin) || roles[pin.Role] || pin.Identity.Device != parent.Device || pin.Identity == parent {
			return ErrIdentity
		}
		for _, previous := range expected {
			if previous == pin.Identity {
				return ErrIdentity
			}
		}
		roles[pin.Role], expected[pin.Name] = true, pin.Identity
	}
	for _, name := range names {
		want, known := expected[name]
		if !known {
			return ErrIdentity
		}
		actual, err := lookup(name)
		if err != nil || actual != want {
			return ErrIdentity
		}
		delete(expected, name)
	}
	if len(expected) != 0 {
		return ErrIdentity
	}
	return nil
}

// Parent is the fixed supervisor cgroup, not an arbitrary caller path. No child
// is created/removed here and unknown or substituted children fail closed.
func validateRoutedDHCPServerCgroupPinsV1(parent *os.File, pins []RoutedDHCPServerCgroupPinV1) error {
	parentID, err := routedDHCPServiceDirectoryV1(parent)
	if err != nil {
		return err
	}
	for _, pin := range pins {
		actual, err := routedDHCPServiceDirectoryV1(pin.Directory)
		if err != nil || actual != pin.Identity || !routedDHCPServerCgroupPinNameV1(pin) || routedDHCPServiceTreeV1(pin.Directory, "", RoutedDHCPServiceCgroupIdentityV1{}) != nil {
			return ErrIdentity
		}
	}
	fd, err := unix.Openat(int(parent.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrIdentity
	}
	directory := os.NewFile(uintptr(fd), "dhcp-server-service-set")
	defer directory.Close()
	entries, err := directory.ReadDir(257)
	if err != nil && err != io.EOF || len(entries) > 256 {
		return ErrIdentity
	}
	var names []string
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrIdentity
		}
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	if err := routedDHCPServerExactChildrenV1(names, pins, parentID, func(name string) (RoutedDHCPServiceCgroupIdentityV1, error) {
		var st unix.Stat_t
		if unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			return RoutedDHCPServiceCgroupIdentityV1{}, ErrIdentity
		}
		return RoutedDHCPServiceCgroupIdentityV1{Device: uint64(st.Dev), Inode: st.Ino}, nil
	}); err != nil {
		return err
	}
	// Parent may contain the two pinned leaves, but cannot delegate controllers
	// or become threaded. Leaves are independently required to have no children.
	kind, err := routedDHCPServiceReadAtV1(parent, "cgroup.type", 32)
	if err != nil || string(kind) != "domain\n" {
		return ErrIdentity
	}
	controllers, err := routedDHCPServiceReadAtV1(parent, "cgroup.subtree_control", 4096)
	if err != nil || strings.TrimSpace(string(controllers)) != "" {
		return ErrIdentity
	}
	return nil
}

func routedDHCPServerCgroupScopeV1(pins []RoutedDHCPServerCgroupPinV1) error {
	if len(pins) == 0 {
		return routedDHCPOwnerCgroupV3() // Existing strict legacy profile.
	}
	parent, err := routedDHCPServiceParentV1()
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := validateRoutedDHCPServerCgroupPinsV1(parent, pins); err != nil {
		return err
	}
	var ownName string
	for _, pin := range pins {
		if pin.Role == "lan" {
			ownName = pin.Name
		}
	}
	if ownName == "" {
		return ErrIdentity
	}
	raw, err := routedDHCPOwnerReadV3("/proc/self/cgroup", 4096)
	if err != nil || string(raw) != "0::"+routedSupervisorCgroupV3+"/"+ownName+"\n" {
		return ErrIdentity
	}
	return nil
}

//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const routedDHCPServiceCgroupVersionV1 = 1

// This identifies a retained kernel object, not a socket's current holder.
type RoutedDHCPServiceCgroupIdentityV1 struct{ Device, Inode uint64 }

type routedDHCPServiceCgroupV1 struct {
	mu                              sync.Mutex
	parent, directory, kill, events *os.File
	identity                        RoutedDHCPServiceCgroupIdentityV1
	name                            string
	closed, removed                 bool
	closeErr                        error
}

func routedDHCPServiceNameV1(incarnation string) (string, error) {
	if !ValidRun(incarnation) {
		return "", ErrIdentity
	}
	return "dhcp-" + incarnation, nil
}

func routedDHCPServiceDirectoryV1(file *os.File) (RoutedDHCPServiceCgroupIdentityV1, error) {
	var id RoutedDHCPServiceCgroupIdentityV1
	if file == nil {
		return id, ErrIdentity
	}
	fd := int(file.Fd())
	flags, e := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	var st unix.Stat_t
	var fs unix.Statfs_t
	if e != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 || unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 || st.Dev == 0 || st.Ino == 0 {
		return id, ErrIdentity
	}
	return RoutedDHCPServiceCgroupIdentityV1{uint64(st.Dev), st.Ino}, nil
}

func routedDHCPServiceReadAtV1(directory *os.File, name string, limit int) ([]byte, error) {
	fd, e := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrIdentity
	}
	f := os.NewFile(uintptr(fd), "dhcp-service-state")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 {
		return nil, ErrIdentity
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if e != nil || len(b) > limit {
		return nil, ErrIdentity
	}
	return b, nil
}

// No prefix allowance: the only permitted child must equal the retained pin.
func routedDHCPServiceTreeV1(parent *os.File, name string, expected RoutedDHCPServiceCgroupIdentityV1) error {
	if _, e := routedDHCPServiceDirectoryV1(parent); e != nil {
		return e
	}
	fd, e := unix.Openat(int(parent.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrIdentity
	}
	d := os.NewFile(uintptr(fd), "dhcp-service-tree")
	defer d.Close()
	entries, e := d.ReadDir(257)
	if e != nil && e != io.EOF || len(entries) > 256 {
		return ErrIdentity
	}
	found := false
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrIdentity
		}
		if !entry.IsDir() {
			continue
		}
		var st unix.Stat_t
		if name == "" || found || entry.Name() != name || unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 || uint64(st.Dev) != expected.Device || st.Ino != expected.Inode {
			return ErrIdentity
		}
		found = true
	}
	if (name != "") != found {
		return ErrIdentity
	}
	kind, e := routedDHCPServiceReadAtV1(parent, "cgroup.type", 32)
	if e != nil || string(kind) != "domain\n" {
		return ErrIdentity
	}
	subtree, e := routedDHCPServiceReadAtV1(parent, "cgroup.subtree_control", 4096)
	if e != nil || strings.TrimSpace(string(subtree)) != "" {
		return ErrIdentity
	}
	return nil
}

func routedDHCPServiceParentV1() (*os.File, error) {
	fd, e := unix.Open("/sys/fs/cgroup"+routedSupervisorCgroupV3, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrIdentity
	}
	f := os.NewFile(uintptr(fd), "dhcp-service-parent")
	if _, e = routedDHCPServiceDirectoryV1(f); e != nil {
		_ = f.Close()
		return nil, e
	}
	return f, nil
}

func newRoutedDHCPServiceCgroupV1(ctx context.Context, incarnation string) (*routedDHCPServiceCgroupV1, error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || routedDHCPOwnerCgroupV3() != nil {
		return nil, ErrIdentity
	}
	name, e := routedDHCPServiceNameV1(incarnation)
	if e != nil {
		return nil, e
	}
	parent, e := routedDHCPServiceParentV1()
	if e != nil {
		return nil, e
	}
	if e = unix.Mkdirat(int(parent.Fd()), name, 0700); e != nil {
		_ = parent.Close()
		return nil, ErrIdentity
	}
	fd, e := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		_ = parent.Close()
		return nil, ErrUnavailable
	} // Preserve unverified residue.
	s := &routedDHCPServiceCgroupV1{parent: parent, directory: os.NewFile(uintptr(fd), "dhcp-service"), name: name}
	s.identity, e = routedDHCPServiceDirectoryV1(s.directory)
	if e == nil {
		e = s.verify()
	}
	if e == nil {
		s.kill, e = s.openControl("cgroup.kill", unix.O_WRONLY)
	}
	if e == nil {
		s.events, e = s.openControl("cgroup.events", unix.O_RDONLY)
	}
	if e != nil || ctx.Err() != nil {
		// No child was launched. Keep the directory on any incomplete identity
		// check so a later launch cannot adopt it or silently erase the failure.
		_ = s.closeFiles()
		return nil, errors.Join(ErrUnavailable, e, ctx.Err())
	}
	return s, nil
}

func (s *routedDHCPServiceCgroupV1) openControl(name string, access int) (*os.File, error) {
	fd, e := unix.Openat(int(s.directory.Fd()), name, access|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "dhcp-service-control")
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || uint64(st.Dev) != s.identity.Device {
		_ = f.Close()
		return nil, ErrIdentity
	}
	return f, nil
}

func (s *routedDHCPServiceCgroupV1) verify() error {
	actual, e := routedDHCPServiceDirectoryV1(s.directory)
	if e != nil || actual != s.identity {
		return ErrIdentity
	}
	if e = routedDHCPServiceTreeV1(s.parent, s.name, s.identity); e != nil {
		return e
	}
	return routedDHCPServiceTreeV1(s.directory, "", RoutedDHCPServiceCgroupIdentityV1{})
}

func (s *routedDHCPServiceCgroupV1) readonly() (*os.File, RoutedDHCPServiceCgroupIdentityV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.verify() != nil {
		return nil, RoutedDHCPServiceCgroupIdentityV1{}, ErrUnavailable
	}
	fd, e := unix.FcntlInt(s.directory.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return nil, RoutedDHCPServiceCgroupIdentityV1{}, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), "retained-dhcp-service"), s.identity, nil
}

func routedDHCPServicePopulatedV1(raw []byte) (bool, error) {
	if len(raw) == 0 || len(raw) > 256 {
		return false, ErrIdentity
	}
	seen := map[string]bool{}
	populated := false
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || seen[fields[0]] || (fields[0] != "populated" && fields[0] != "frozen") || (fields[1] != "0" && fields[1] != "1") {
			return false, ErrIdentity
		}
		seen[fields[0]] = true
		if fields[0] == "populated" {
			populated = fields[1] == "1"
		} else if fields[1] != "0" {
			return false, ErrIdentity
		}
	}
	if len(seen) != 2 {
		return false, ErrIdentity
	}
	return populated, nil
}

// Process drainage only: callers retain a readonly duplicate until a separate
// complete socket observation proves physical absence of the old origin.
func drainRoutedDHCPServiceV1(ctx context.Context, verify func() error, kill func() error, populated func() (bool, error), remove func() error) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if e := verify(); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e := kill(); e != nil {
		return e
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e := verify(); e != nil {
			return e
		}
		p, e := populated()
		if e != nil {
			return e
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !p {
			if e = verify(); e != nil {
				return e
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return remove()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func (s *routedDHCPServiceCgroupV1) drain(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	e := drainRoutedDHCPServiceV1(ctx, s.verify, func() error {
		n, e := unix.Write(int(s.kill.Fd()), []byte("1\n"))
		if e != nil || n != 2 {
			return ErrUnavailable
		}
		return nil
	}, func() (bool, error) {
		var b [257]byte
		n, e := unix.Pread(int(s.events.Fd()), b[:], 0)
		if e != nil {
			return false, ErrUnavailable
		}
		return routedDHCPServicePopulatedV1(b[:n])
	}, func() error {
		if unix.Unlinkat(int(s.parent.Fd()), s.name, unix.AT_REMOVEDIR) != nil {
			return ErrUnavailable
		}
		s.removed = true
		return nil
	})
	if e != nil {
		s.closeErr = e
		return e
	} // Retain the owned descriptors/directory on failed drain.
	s.closeErr = s.closeFiles()
	return s.closeErr
}

func (s *routedDHCPServiceCgroupV1) closeFiles() error {
	var result error
	for _, f := range []*os.File{s.kill, s.events, s.directory, s.parent} {
		if f != nil {
			result = errors.Join(result, f.Close())
		}
	}
	return result
}

func validateRoutedDHCPServiceRoleV1(pin *os.File, incarnation string, version int, expected RoutedDHCPServiceCgroupIdentityV1) error {
	name, e := routedDHCPServiceNameV1(incarnation)
	if e != nil || !routedDHCPServiceBootstrapValidV1(version, expected) {
		return ErrIdentity
	}
	actual, e := routedDHCPServiceDirectoryV1(pin)
	if e != nil || actual != expected {
		return ErrIdentity
	}
	current, e := routedDHCPOwnerReadV3("/proc/self/cgroup", 4096)
	if e != nil || string(current) != "0::"+routedSupervisorCgroupV3+"/"+name+"\n" {
		return ErrIdentity
	}
	parent, e := routedDHCPServiceParentV1()
	if e != nil {
		return e
	}
	defer parent.Close()
	if e = routedDHCPServiceTreeV1(parent, name, expected); e != nil {
		return e
	}
	return routedDHCPServiceTreeV1(pin, "", RoutedDHCPServiceCgroupIdentityV1{})
}

func routedDHCPServiceBootstrapValidV1(version int, id RoutedDHCPServiceCgroupIdentityV1) bool {
	return version == routedDHCPServiceCgroupVersionV1 && id.Device != 0 && id.Inode != 0
}

//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// The pair belongs to a network incarnation, not to a feature enablement. An
// inactive feature has an empty reserved slot, never a process or live config.
// Root retains write controls. Other roles receive readonly duplicates only.
type RoutedDHCPServerServiceSetV1 struct {
	mu        sync.Mutex
	parent    *os.File
	wan, lan  *routedDHCPServiceCgroupV1
	retiring  bool
	retireErr error
}

type RoutedDHCPServerServiceSetOptionsV1 struct {
	WANEnabled, LANEnabled         bool
	WANIncarnation, LANIncarnation string
}

func PrepareRoutedDHCPServerServiceSetV1(ctx context.Context, o RoutedDHCPServerServiceSetOptionsV1) (*RoutedDHCPServerServiceSetV1, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrIdentity
	}
	if !o.WANEnabled && !o.LANEnabled {
		return nil, nil
	}
	wanName, err := routedDHCPServerCgroupNameV1("wan", o.WANIncarnation)
	if err != nil {
		return nil, err
	}
	lanName, err := routedDHCPServerCgroupNameV1("lan", o.LANIncarnation)
	if err != nil {
		return nil, err
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || routedDHCPOwnerCgroupV3() != nil {
		return nil, ErrIdentity
	}
	parent, err := routedDHCPServiceParentV1()
	if err != nil {
		return nil, err
	}
	s := &RoutedDHCPServerServiceSetV1{parent: parent}
	// Failures preserve created slots. An unverified partial tree is never
	// adopted by a later constructor or recursively removed by a computed path.
	s.wan, err = routedDHCPServerCreateSlotV1(parent, wanName)
	if err == nil {
		s.lan, err = routedDHCPServerCreateSlotV1(parent, lanName)
	}
	if err == nil {
		err = s.verifyUnderV1()
	}
	if err != nil || ctx.Err() != nil {
		_ = s.closeFilesV1()
		return nil, errors.Join(ErrUnavailable, err, ctx.Err())
	}
	return s, nil
}

func routedDHCPServerCreateSlotV1(parent *os.File, name string) (*routedDHCPServiceCgroupV1, error) {
	if unix.Mkdirat(int(parent.Fd()), name, 0700) != nil {
		return nil, ErrUnavailable
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	s := &routedDHCPServiceCgroupV1{name: name, directory: os.NewFile(uintptr(fd), "reserved-dhcp-service")}
	parentFD, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err == nil {
		s.parent = os.NewFile(uintptr(parentFD), "reserved-dhcp-parent")
		s.identity, err = routedDHCPServiceDirectoryV1(s.directory)
	}
	if err == nil {
		s.kill, err = s.openControl("cgroup.kill", unix.O_WRONLY)
	}
	if err == nil {
		s.events, err = s.openControl("cgroup.events", unix.O_RDONLY)
	}
	if err != nil {
		_ = s.closeFiles()
		return nil, ErrUnavailable
	}
	return s, nil
}

func (s *RoutedDHCPServerServiceSetV1) pinsUnderV1() []RoutedDHCPServerCgroupPinV1 {
	if s == nil || s.wan == nil || s.lan == nil {
		return nil
	}
	return []RoutedDHCPServerCgroupPinV1{{Role: "wan", Name: s.wan.name, Identity: s.wan.identity, Directory: s.wan.directory}, {Role: "lan", Name: s.lan.name, Identity: s.lan.identity, Directory: s.lan.directory}}
}

func (s *RoutedDHCPServerServiceSetV1) verifyUnderV1() error {
	if s == nil || s.parent == nil || s.wan == nil || s.lan == nil {
		return ErrIdentity
	}
	return validateRoutedDHCPServerCgroupPinsV1(s.parent, s.pinsUnderV1())
}

func (s *RoutedDHCPServerServiceSetV1) ReadOnlyPinsV1() ([]RoutedDHCPServerCgroupPinV1, error) {
	if s == nil {
		return nil, ErrIdentity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retiring || s.verifyUnderV1() != nil {
		return nil, ErrUnavailable
	}
	var out []RoutedDHCPServerCgroupPinV1
	for _, pin := range s.pinsUnderV1() {
		fd, err := unix.FcntlInt(pin.Directory.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			cleanupErr := ErrUnavailable
			for _, p := range out {
				cleanupErr = errors.Join(cleanupErr, p.Directory.Close())
			}
			return nil, cleanupErr
		}
		pin.Directory = os.NewFile(uintptr(fd), "readonly-dhcp-service-pin")
		out = append(out, pin)
	}
	return out, nil
}

func (s *RoutedDHCPServerServiceSetV1) drainUnderV1(ctx context.Context, slot *routedDHCPServiceCgroupV1) error {
	if slot == nil {
		return ErrIdentity
	}
	return drainRoutedDHCPServiceV1(ctx, s.verifyUnderV1, func() error {
		n, err := unix.Write(int(slot.kill.Fd()), []byte("1\n"))
		if err != nil || n != 2 {
			return ErrUnavailable
		}
		return nil
	}, func() (bool, error) {
		var raw [257]byte
		n, err := unix.Pread(int(slot.events.Fd()), raw[:], 0)
		if err != nil {
			return false, ErrUnavailable
		}
		return routedDHCPServicePopulatedV1(raw[:n])
	}, func() error { return nil })
}

// DrainFeature leaves both reserved inodes intact. Only whole-incarnation
// retirement may unlink them. It never publishes feature state or readiness.
func (s *RoutedDHCPServerServiceSetV1) DrainFeatureV1(ctx context.Context, role string) error {
	if s == nil || ctx == nil {
		return ErrIdentity
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrIdentity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retiring {
		return ErrUnavailable
	}
	switch role {
	case "wan":
		return s.drainUnderV1(ctx, s.wan)
	case "lan":
		return s.drainUnderV1(ctx, s.lan)
	default:
		return ErrIdentity
	}
}

// Root calls this only after closing forwarding and retiring selected work.
// On uncertain/partial cleanup it preserves the tree and returns an error;
// outer whole-cgroup containment and manual recovery remain available.
func (s *RoutedDHCPServerServiceSetV1) DestroyV1(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrIdentity
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrIdentity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retiring {
		return s.retireErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.retiring = true
	finish := func(err error) error { s.retireErr = errors.Join(ErrUnavailable, err); return s.retireErr }
	if err := s.drainUnderV1(ctx, s.wan); err != nil {
		return finish(err)
	}
	if err := s.drainUnderV1(ctx, s.lan); err != nil {
		return finish(err)
	}
	if ctx.Err() != nil {
		return finish(ctx.Err())
	}
	if unix.Unlinkat(int(s.parent.Fd()), s.lan.name, unix.AT_REMOVEDIR) != nil {
		return finish(ErrUnavailable)
	}
	if routedDHCPServiceTreeV1(s.parent, s.wan.name, s.wan.identity) != nil || ctx.Err() != nil {
		return finish(ErrIdentity)
	}
	if unix.Unlinkat(int(s.parent.Fd()), s.wan.name, unix.AT_REMOVEDIR) != nil {
		return finish(ErrUnavailable)
	}
	if routedDHCPServiceTreeV1(s.parent, "", RoutedDHCPServiceCgroupIdentityV1{}) != nil {
		return finish(ErrIdentity)
	}
	s.retireErr = s.closeFilesV1()
	return s.retireErr
}

func (s *RoutedDHCPServerServiceSetV1) closeFilesV1() error {
	var err error
	for _, slot := range []*routedDHCPServiceCgroupV1{s.wan, s.lan} {
		if slot != nil {
			err = errors.Join(err, slot.closeFiles())
		}
	}
	if s.parent != nil {
		err = errors.Join(err, s.parent.Close())
	}
	return err
}

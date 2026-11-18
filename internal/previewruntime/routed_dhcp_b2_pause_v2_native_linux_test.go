//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"golang.org/x/sys/unix"
)

const nativeDHCPB2VersionV2 = 2

func nativeDHCPPauseCleanupV2(resume func() error, collect func(), drain func() error) error {
	err := resume()
	collect()
	return errors.Join(err, drain())
}

type nativeDHCPPauseReportV2 struct {
	StopBefore int64 `json:"stop_before_boot_ns"`
	StopAfter  int64 `json:"stop_after_boot_ns"`
	ContBefore int64 `json:"cont_before_boot_ns"`
	ContAfter  int64 `json:"cont_after_boot_ns"`
}

// Operations are injectable only inside this test file, so cancellation and
// cleanup regressions never signal a real process in the unprivileged suite.
type nativeDHCPPauseOpsV2 struct {
	verify func() error
	signal func(unix.Signal) error
	now    func() (int64, error)
	wait   func(context.Context, int64) error
}

func nativeDHCPPauseSequenceV2(ctx context.Context, g int64, o nativeDHCPPauseOpsV2) (r nativeDHCPPauseReportV2, err error) {
	if g <= 0 || g > math.MaxInt64-int64(23*time.Second) || ctx == nil || ctx.Err() != nil || o.verify == nil || o.signal == nil || o.now == nil || o.wait == nil {
		return r, ErrIdentity
	}
	if err = o.verify(); err != nil {
		return r, err
	}
	if err = o.wait(ctx, g+int64(21450*time.Millisecond)); err != nil {
		return r, err
	}
	if err = o.verify(); err != nil {
		return r, err
	}
	paused := false
	defer func() {
		if paused {
			err = errors.Join(err, o.signal(unix.SIGCONT))
		}
	}()
	r.StopBefore, err = o.now()
	if err != nil || r.StopBefore >= g+int64(21500*time.Millisecond) {
		return r, ErrUnavailable
	}
	// A signal error may be uncertain; CONT is attempted even if STOP reports it.
	paused = true
	if err = o.signal(unix.SIGSTOP); err != nil {
		return r, err
	}
	r.StopAfter, err = o.now()
	if err != nil {
		return r, err
	}
	if err = o.wait(ctx, g+int64(22600*time.Millisecond)); err != nil {
		return r, err
	}
	if err = o.verify(); err != nil {
		return r, err
	}
	r.ContBefore, err = o.now()
	if err != nil {
		return r, err
	}
	if err = o.signal(unix.SIGCONT); err != nil {
		return r, err
	}
	paused = false
	r.ContAfter, err = o.now()
	if err != nil {
		return r, err
	}
	if err = o.verify(); err != nil {
		return r, err
	}
	return r, nativeDHCPPauseBoundsV2(g, r)
}

func nativeDHCPPauseBoundsV2(g int64, r nativeDHCPPauseReportV2) error {
	if g <= 0 || g > math.MaxInt64-int64(23*time.Second) || r.StopBefore < g+int64(21450*time.Millisecond) || r.StopAfter < r.StopBefore || r.StopAfter >= g+int64(21500*time.Millisecond) || r.ContBefore < g+int64(22600*time.Millisecond) || r.ContAfter < r.ContBefore || r.ContAfter-r.StopBefore >= int64(1700*time.Millisecond) {
		return ErrUnavailable
	}
	return nil
}

// This holds only the already authenticated Go acquisition owner's pidfd.
// It never addresses a PID from a name, environment variable or report string.
type nativeDHCPB2PauseV2 struct {
	mu           sync.Mutex
	pin, service *os.File
	owner        networkexecutor.LeaseOwner
	mount        uint64
	serviceID    RoutedDHCPServiceCgroupIdentityV1
	paused       bool
	err          error
}

type nativeDHCPPauseIdentityV2 struct {
	Start          uint64
	Parent         int
	Network, Mount uint64
	Group          string
	Service        RoutedDHCPServiceCgroupIdentityV1
}

func nativeDHCPPauseMatchesV2(owner networkexecutor.LeaseOwner, mount uint64, service RoutedDHCPServiceCgroupIdentityV1, got nativeDHCPPauseIdentityV2) bool {
	name, err := routedDHCPServiceNameV1(owner.Incarnation)
	return err == nil && owner.PID > 1 && owner.PID != uint32(os.Getpid()) && owner.StartTicks > 0 && owner.Namespace > 0 && ValidRun(owner.RunID) && mount > 0 && service.Device > 0 && service.Inode > 0 && got.Start == owner.StartTicks && got.Parent == os.Getpid() && got.Network == owner.Namespace && got.Mount == mount && got.Service == service && got.Group == "0::"+routedSupervisorCgroupV3+"/"+name+"\n"
}

func (p *nativeDHCPB2PauseV2) capture(o *RoutedDHCPOwnerV3, pin, service *os.File) error {
	if p == nil || o == nil || pin == nil || service == nil || os.Geteuid() != 0 {
		return ErrIdentity
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	b := o.deferred
	if p.pin != nil || o.closed || o.profile != 4 || !routedDHCPDeferredBindingValidV4(b) || b.Owner.PID == uint32(os.Getpid()) {
		return ErrIdentity
	}
	id, err := routedDHCPServiceDirectoryV1(service)
	if err != nil {
		return err
	}
	a, err := unix.FcntlInt(pin.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	z, err := unix.FcntlInt(service.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(a)
		return err
	}
	p.pin, p.service = os.NewFile(uintptr(a), "native-b2-owner"), os.NewFile(uintptr(z), "native-b2-cgroup")
	p.owner, p.mount, p.serviceID = b.Owner, b.MountNamespace, id
	return nil
}

// No owner mutex or Current RPC is used while the owner is stopped.
func (p *nativeDHCPB2PauseV2) verify() error {
	if p == nil || p.pin == nil || p.service == nil || p.owner.PID <= 1 || p.owner.PID == uint32(os.Getpid()) || p.owner.StartTicks == 0 || p.owner.Namespace == 0 || p.mount == 0 || !ValidRun(p.owner.Incarnation) || !ValidRun(p.owner.RunID) || !routedDHCPOwnerPIDFDAliveV3(p.pin, int(p.owner.PID)) {
		return ErrIdentity
	}
	pid := int(p.owner.PID)
	start, parent, err := routedDHCPOwnerProcessV3(pid)
	net, netErr := namespaceID(fmt.Sprintf("/proc/%d/ns/net", pid))
	mount, mountErr := namespaceID(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	group, groupErr := routedDHCPOwnerReadV3("/proc/"+strconv.Itoa(pid)+"/cgroup", 4096)
	id, idErr := routedDHCPServiceDirectoryV1(p.service)
	if err != nil || netErr != nil || mountErr != nil || groupErr != nil || idErr != nil || !nativeDHCPPauseMatchesV2(p.owner, p.mount, p.serviceID, nativeDHCPPauseIdentityV2{start, parent, net, mount, string(group), id}) {
		return ErrIdentity
	}
	return nil
}

func nativeDHCPPauseWaitV2(ctx context.Context, target int64) error {
	now, err := routedDHCPOwnerBootNowV3()
	if err != nil || now >= target {
		return ErrUnavailable
	}
	timer := time.NewTimer(time.Duration(target - now))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *nativeDHCPB2PauseV2) run(ctx context.Context, g int64) (r nativeDHCPPauseReportV2, err error) {
	if p == nil {
		return r, ErrIdentity
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if g <= 0 || p.err != nil || p.paused || p.verify() != nil {
		return r, ErrIdentity
	}
	r, err = nativeDHCPPauseSequenceV2(ctx, g, nativeDHCPPauseOpsV2{p.verify, func(signal unix.Signal) error {
		if signal == unix.SIGSTOP {
			p.paused = true
		}
		e := unix.PidfdSendSignal(int(p.pin.Fd()), signal, nil, 0)
		if signal == unix.SIGCONT && e == nil {
			p.paused = false
		}
		return e
	}, routedDHCPOwnerBootNowV3, nativeDHCPPauseWaitV2})
	p.err = err
	return r, err
}

func (p *nativeDHCPB2PauseV2) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var err error
	if p.paused && p.pin != nil {
		err = unix.PidfdSendSignal(int(p.pin.Fd()), unix.SIGCONT, nil, 0)
		if err == nil {
			p.paused = false
		}
	}
	if p.pin != nil {
		err = errors.Join(err, p.pin.Close())
		p.pin = nil
	}
	if p.service != nil {
		err = errors.Join(err, p.service.Close())
		p.service = nil
	}
	return errors.Join(p.err, err)
}

func TestNativeDHCPB2PauseV2Bounds(t *testing.T) {
	g := int64(time.Second)
	r := nativeDHCPPauseReportV2{g + int64(21450*time.Millisecond), g + int64(21451*time.Millisecond), g + int64(22600*time.Millisecond), g + int64(22601*time.Millisecond)}
	if nativeDHCPPauseBoundsV2(g, r) != nil {
		t.Fatal("fixed pause rejected")
	}
	for _, mutate := range []func(*nativeDHCPPauseReportV2){
		func(r *nativeDHCPPauseReportV2) { r.StopBefore-- },
		func(r *nativeDHCPPauseReportV2) { r.StopAfter = g + int64(21500*time.Millisecond) },
		func(r *nativeDHCPPauseReportV2) { r.ContBefore-- },
		func(r *nativeDHCPPauseReportV2) { r.ContAfter = r.StopBefore + int64(1700*time.Millisecond) },
		func(r *nativeDHCPPauseReportV2) { r.ContAfter = r.ContBefore - 1 },
	} {
		bad := r
		mutate(&bad)
		if nativeDHCPPauseBoundsV2(g, bad) == nil {
			t.Fatal("invalid pause accepted", bad)
		}
	}
}

func TestNativeDHCPB2PauseV2RejectsUnpinnedOwnerWithoutSignaling(t *testing.T) {
	for _, p := range []*nativeDHCPB2PauseV2{nil, {}, {owner: networkexecutor.LeaseOwner{PID: uint32(os.Getpid())}}} {
		if p.verify() == nil {
			t.Fatal("untrusted owner accepted")
		}
		if p != nil {
			if _, err := p.run(context.Background(), 1); err == nil {
				t.Fatal("unpinned owner paused")
			}
			if p.Close() != nil {
				t.Fatal("empty cleanup")
			}
		}
	}
}

func TestNativeDHCPB2PauseV2AlwaysContinuesOnFailure(t *testing.T) {
	for _, fail := range []string{"", "verify1", "wait1", "verify2", "now1", "stop", "now2", "wait2", "verify3", "now3", "cont", "now4", "verify4"} {
		t.Run(fail, func(t *testing.T) {
			g := int64(time.Second)
			times := []int64{g + int64(21450*time.Millisecond), g + int64(21451*time.Millisecond), g + int64(22600*time.Millisecond), g + int64(22601*time.Millisecond)}
			calls := map[string]int{}
			check := func(name string) error {
				calls[name]++
				key := name
				if name != "stop" && name != "cont" {
					key += strconv.Itoa(calls[name])
				}
				if key == fail && calls[name] == 1 || key == fail && name != "stop" && name != "cont" {
					return ErrUnavailable
				}
				return nil
			}
			o := nativeDHCPPauseOpsV2{
				verify: func() error { return check("verify") },
				wait:   func(context.Context, int64) error { return check("wait") },
				now:    func() (int64, error) { err := check("now"); return times[calls["now"]-1], err },
				signal: func(s unix.Signal) error {
					if s == unix.SIGSTOP {
						return check("stop")
					}
					if s == unix.SIGCONT {
						return check("cont")
					}
					t.Fatal("non-allowlisted signal")
					return ErrIdentity
				},
			}
			_, err := nativeDHCPPauseSequenceV2(context.Background(), g, o)
			if (fail == "") != (err == nil) {
				t.Fatal("unexpected pause outcome", err)
			}
			if calls["stop"] > 0 && calls["cont"] == 0 {
				t.Fatal("stopped or uncertain owner did not receive cleanup CONT")
			}
			if calls["stop"] == 0 && calls["cont"] != 0 {
				t.Fatal("unverified owner was signaled")
			}
			if calls["stop"] > 1 || calls["cont"] > 2 {
				t.Fatal("unbounded cleanup signal retry")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if _, err := nativeDHCPPauseSequenceV2(ctx, 1, nativeDHCPPauseOpsV2{verify: func() error { called = true; return nil }}); err == nil || called {
		t.Fatal("canceled or incomplete fixture signaled")
	}
}

func TestNativeDHCPB2PauseV2RejectsChangedIdentity(t *testing.T) {
	owner := networkexecutor.LeaseOwner{PID: uint32(os.Getpid() + 1000), StartTicks: 42, Namespace: 71, Incarnation: strings.Repeat("a", 32), RunID: strings.Repeat("b", 32)}
	service := RoutedDHCPServiceCgroupIdentityV1{17, 19}
	name, err := routedDHCPServiceNameV1(owner.Incarnation)
	if err != nil {
		t.Fatal(err)
	}
	valid := nativeDHCPPauseIdentityV2{42, os.Getpid(), 71, 73, "0::" + routedSupervisorCgroupV3 + "/" + name + "\n", service}
	if !nativeDHCPPauseMatchesV2(owner, 73, service, valid) {
		t.Fatal("fixed owned identity rejected")
	}
	for _, mutate := range []func(*nativeDHCPPauseIdentityV2){
		func(g *nativeDHCPPauseIdentityV2) { g.Start++ },
		func(g *nativeDHCPPauseIdentityV2) { g.Parent++ },
		func(g *nativeDHCPPauseIdentityV2) { g.Network++ },
		func(g *nativeDHCPPauseIdentityV2) { g.Mount++ },
		func(g *nativeDHCPPauseIdentityV2) { g.Group = "0::/\n" },
		func(g *nativeDHCPPauseIdentityV2) { g.Service.Inode++ },
		func(g *nativeDHCPPauseIdentityV2) { g.Service.Device++ },
	} {
		bad := valid
		mutate(&bad)
		if nativeDHCPPauseMatchesV2(owner, 73, service, bad) {
			t.Fatal("changed process/ns/cgroup identity accepted", bad)
		}
	}
	for _, pid := range []uint32{0, 1, uint32(os.Getpid())} {
		bad := owner
		bad.PID = pid
		if nativeDHCPPauseMatchesV2(bad, 73, service, valid) {
			t.Fatal("unowned process accepted")
		}
	}
}

func TestNativeDHCPB2PauseV2CancellationAfterStopContinuesOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := int64(time.Second)
	waits, stops, continues := 0, 0, 0
	o := nativeDHCPPauseOpsV2{
		verify: func() error { return nil },
		now:    func() (int64, error) { return g + int64(21450*time.Millisecond), nil },
		wait: func(ctx context.Context, _ int64) error {
			waits++
			if waits == 2 {
				cancel()
				return ctx.Err()
			}
			return nil
		},
		signal: func(s unix.Signal) error {
			switch s {
			case unix.SIGSTOP:
				stops++
			case unix.SIGCONT:
				continues++
			default:
				t.Fatal("unapproved signal")
			}
			return nil
		},
	}
	if _, err := nativeDHCPPauseSequenceV2(ctx, g, o); !errors.Is(err, context.Canceled) || stops != 1 || continues != 1 {
		t.Fatal("cancellation left owner stopped", err, stops, continues)
	}
}

func TestNativeDHCPB2PauseV2BackupContinuePrecedesCollectionAndDrain(t *testing.T) {
	events := []string{}
	want := errors.New("uncertain first CONT")
	g := int64(time.Second)
	paused := false
	continues, clocks := 0, 0
	times := []int64{g + int64(21450*time.Millisecond), g + int64(21451*time.Millisecond), g + int64(22600*time.Millisecond)}
	signal := func(s unix.Signal) error {
		if s == unix.SIGSTOP {
			paused = true
			events = append(events, "STOP")
			return nil
		}
		continues++
		events = append(events, fmt.Sprintf("CONT%d", continues))
		if continues <= 2 {
			return want
		}
		paused = false
		return nil
	}
	_, sequenceErr := nativeDHCPPauseSequenceV2(context.Background(), g, nativeDHCPPauseOpsV2{func() error { return nil }, signal, func() (int64, error) { n := times[clocks]; clocks++; return n, nil }, func(context.Context, int64) error { return nil }})
	if !errors.Is(sequenceErr, want) || !paused {
		t.Fatal("uncertain resume was not retained", sequenceErr, paused)
	}
	err := nativeDHCPPauseCleanupV2(func() error { return errors.Join(sequenceErr, signal(unix.SIGCONT)) }, func() {
		if paused {
			t.Fatal("collector ran before backup CONT")
		}
		events = append(events, "collect")
	}, func() error {
		if paused {
			t.Fatal("drain ran before backup CONT")
		}
		events = append(events, "drain")
		return nil
	})
	if !errors.Is(err, want) || paused || strings.Join(events, ",") != "STOP,CONT1,CONT2,CONT3,collect,drain" {
		t.Fatal("uncertain resume hidden or cleanup order reversed", err, events)
	}
}

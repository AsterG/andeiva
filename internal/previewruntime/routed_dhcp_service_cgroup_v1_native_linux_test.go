//go:build linux

package previewruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Root runs this only in the reserved, otherwise absent supervisor unit. It
// exercises cgroup operations on newly created children; no network mutation,
// DHCP acquisition, listener qualification or service installation is tested.
func TestNativeRoutedDHCPServiceCgroupV1(t *testing.T) {
	if os.Getenv("ANDEIVA_NATIVE_DHCP_SERVICE_CGROUP_V1") != "1" {
		t.Skip("requires authorized isolated root laboratory unit")
	}
	if os.Getenv("CI") != "" || os.Getuid() != 0 || os.Geteuid() != 0 || routedDHCPOwnerCgroupV3() != nil {
		t.Fatal("invalid root laboratory scope")
	}
	if trustedRoutedExecutableV3("/usr/bin/sleep") != nil {
		t.Fatal("untrusted fixed test executable")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	s, err := newRoutedDHCPServiceCgroupV1(context.Background(), hex.EncodeToString(nonce[:]))
	if err != nil {
		t.Fatal("create exclusive service cgroup", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := s.drain(ctx); err != nil {
			t.Error("retained cgroup after unsuccessful drain", err)
		}
	})
	pin, id, err := s.readonly()
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if id != s.identity {
		t.Fatal("readonly identity changed")
	}
	if _, err := newRoutedDHCPServiceCgroupV1(context.Background(), hex.EncodeToString(nonce[:])); err == nil {
		t.Fatal("existing child adopted")
	}
	if routedDHCPServiceTreeV1(s.parent, s.name, RoutedDHCPServiceCgroupIdentityV1{id.Device, id.Inode + 1}) == nil {
		t.Fatal("wrong object accepted")
	}
	// The root caller remains in its parent cgroup, so it cannot masquerade as
	// the child role even with a genuine pin and matching bootstrap metadata.
	if validateRoutedDHCPServiceRoleV1(pin, hex.EncodeToString(nonce[:]), 1, id) == nil {
		t.Fatal("wrong process membership accepted")
	}
	var completed []<-chan error
	var pidfds []*os.File
	for range 2 {
		pidfd := -1
		cmd := exec.Command("/usr/bin/sleep", "60")
		cmd.Env = []string{"PATH=/usr/bin", "LC_ALL=C"}
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(s.directory.Fd()), PidFD: &pidfd, Pdeathsig: syscall.SIGKILL}
		started := make(chan error, 1)
		done := make(chan error, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			e := cmd.Start()
			started <- e
			if e == nil {
				done <- cmd.Wait()
			}
		}()
		if err := <-started; err != nil {
			t.Fatal("clone into service cgroup", err)
		}
		f := os.NewFile(uintptr(pidfd), "native-service-pidfd")
		defer f.Close()
		pidfds = append(pidfds, f)
		t.Cleanup(func() { _ = cmd.Process.Kill() })
		completed = append(completed, done)
		raw, err := routedDHCPOwnerReadV3("/proc/"+strconv.Itoa(cmd.Process.Pid)+"/cgroup", 4096)
		if err != nil || string(raw) != "0::"+routedSupervisorCgroupV3+"/"+s.name+"\n" || !routedDHCPOwnerPIDFDAliveV3(f, cmd.Process.Pid) {
			t.Fatal("child did not enter pinned group before exec")
		}
	}
	data, err := routedDHCPServiceReadAtV1(s.directory, "cgroup.events", 256)
	populated, parseErr := routedDHCPServicePopulatedV1(data)
	if err != nil || parseErr != nil || !populated {
		t.Fatal("live child population not observed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = s.drain(ctx); err != nil {
		t.Fatal("kill/drain/remove", err)
	}
	for _, done := range completed {
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("test child unexpectedly completed successfully")
			}
		case <-ctx.Done():
			t.Fatal("child was not reaped within drain deadline")
		}
	}
	for _, fd := range pidfds {
		poll := []unix.PollFd{{Fd: int32(fd.Fd()), Events: unix.POLLIN}}
		if n, e := unix.Poll(poll, 0); e != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
			t.Fatal("pidfd is not dead after drain")
		}
	}
	if retained, e := routedDHCPServiceDirectoryV1(pin); e != nil || retained != id {
		t.Fatal("independent readonly pin did not survive removal")
	}
	data, err = routedDHCPServiceReadAtV1(pin, "cgroup.events", 256)
	if err == nil { // Kernfs may reject reads from an offline cgroup.
		if p, e := routedDHCPServicePopulatedV1(data); e != nil || p {
			t.Fatal("retained group still populated")
		}
	}
	if routedDHCPOwnerCgroupV3() != nil {
		t.Fatal("parent retains unexpected child cgroup")
	}
	if _, _, e := s.readonly(); e == nil {
		t.Fatal("closed service issued a new pin")
	}
	t.Log("processes_drained=true retained_identity=true socket_absence_tested=false acquisition_tested=false")
}

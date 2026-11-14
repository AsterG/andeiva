//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func routedDHCPOwnerBootNowV3() (int64, error) {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return ts.Nano(), err
}
func routedDHCPOwnerReadV3(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- Callers use fixed proc/cgroup paths or checked numeric process IDs.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, ErrIdentity
	}
	b, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	if errors.Join(readErr, f.Close()) != nil || int64(len(b)) > limit {
		return nil, ErrIdentity
	}
	return b, nil
}
func routedDHCPOwnerStatV3(raw []byte, pid int) (uint64, int, error) {
	end := strings.LastIndexByte(string(raw), ')')
	start := strings.IndexByte(string(raw), ' ')
	if pid <= 1 || start < 1 || string(raw[:start]) != strconv.Itoa(pid) || end <= start || len(raw) > 8192 {
		return 0, 0, ErrIdentity
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return 0, 0, ErrIdentity
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	parent, parentErr := strconv.Atoi(fields[1])
	if err != nil || parentErr != nil || ticks == 0 || parent <= 0 || fields[0] == "Z" || fields[0] == "X" {
		return 0, 0, ErrIdentity
	}
	return ticks, parent, nil
}
func routedDHCPOwnerProcessV3(pid int) (uint64, int, error) {
	if pid <= 1 || pid > math.MaxInt32 {
		return 0, 0, ErrIdentity
	}
	raw, err := routedDHCPOwnerReadV3("/proc/"+strconv.Itoa(pid)+"/stat", 8192)
	if err != nil {
		return 0, 0, err
	}
	return routedDHCPOwnerStatV3(raw, pid)
}
func routedDHCPOwnerPIDFDAliveV3(file *os.File, pid int) bool {
	if file == nil || pid <= 1 {
		return false
	}
	fd := file.Fd()
	if fd > math.MaxInt32 {
		return false
	}
	raw, err := routedDHCPOwnerReadV3("/proc/self/fdinfo/"+strconv.FormatUint(uint64(fd), 10), 4096)
	if err != nil {
		return false
	}
	seen := false
	for _, line := range strings.Split(string(raw), "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok && key == "Pid" {
			if seen || strings.TrimSpace(value) != strconv.Itoa(pid) {
				return false
			}
			seen = true
		}
	}
	if !seen {
		return false
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	return err == nil && n == 0 && poll[0].Revents == 0
}
func routedDHCPOwnerPinV3(pid, parent int, netNS, mountNS uint64) (*os.File, uint64, error) {
	if pid <= 1 || pid > math.MaxInt32 || parent <= 1 || netNS == 0 || mountNS == 0 {
		return nil, 0, ErrIdentity
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, 0, ErrIdentity
	}
	file := os.NewFile(uintptr(fd), "dhcp-owner-pidfd")
	fail := func() (*os.File, uint64, error) { _ = file.Close(); return nil, 0, ErrIdentity }
	ticks, ppid, err := routedDHCPOwnerProcessV3(pid)
	if err != nil || ppid != parent {
		return fail()
	}
	for kind, want := range map[string]uint64{"net": netNS, "mnt": mountNS} {
		actual, e := namespaceID("/proc/" + strconv.Itoa(pid) + "/ns/" + kind)
		if e != nil || actual != want {
			return fail()
		}
	}
	after, ppid, err := routedDHCPOwnerProcessV3(pid)
	if err != nil || after != ticks || ppid != parent || !routedDHCPOwnerPIDFDAliveV3(file, pid) {
		return fail()
	}
	return file, ticks, nil
}
func routedDHCPOwnerPipeV3(f *os.File, access int) bool {
	if f == nil || f.Fd() > math.MaxInt {
		return false
	}
	var st unix.Stat_t
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	return err == nil && flags&unix.O_ACCMODE == access && unix.Fstat(int(f.Fd()), &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFIFO && st.Uid == 0 && st.Mode&0077 == 0
}
func routedDHCPOwnerNamespaceV3(f *os.File, kind int, want uint64) bool {
	if f == nil || f.Fd() > math.MaxInt {
		return false
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	actual, err := unix.IoctlRetInt(int(f.Fd()), unix.NS_GET_NSTYPE)
	return err == nil && actual == kind && unix.Fstat(int(f.Fd()), &st) == nil && st.Ino == want && unix.Fstatfs(int(f.Fd()), &fs) == nil && fs.Type == unix.NSFS_MAGIC
}
func routedDHCPOwnerCgroupV3() error {
	raw, err := routedDHCPOwnerReadV3("/proc/self/cgroup", 4096)
	if err != nil || string(raw) != "0::"+routedSupervisorCgroupV3+"\n" {
		return ErrIdentity
	}
	dir, err := routedDHCPServiceParentV1()
	if err != nil {
		return ErrIdentity
	}
	defer dir.Close()
	return routedDHCPServiceTreeV1(dir, "", RoutedDHCPServiceCgroupIdentityV1{})
}

func NewRoutedDHCPOwnerReaderV3(files RoutedDHCPOwnerFilesV3, binding RoutedDHCPOwnerBindingV3) (*RoutedDHCPOwnerReaderV3, error) {
	if !routedDHCPOwnerBindingValidV3(binding) || !routedDHCPOwnerPipeV3(files.Request, unix.O_WRONLY) || !routedDHCPOwnerPipeV3(files.Reply, unix.O_RDONLY) || !routedDHCPOwnerPIDFDAliveV3(files.RolePIDFD, int(binding.RolePID)) || !routedDHCPOwnerPIDFDAliveV3(files.LeasePIDFD, int(binding.Owner.PID)) {
		return nil, ErrIdentity
	}
	raw, err := jsonOwnerBindingV3(binding)
	if err != nil {
		return nil, err
	}
	r := &RoutedDHCPOwnerReaderV3{gate: make(chan struct{}, 1), files: files, scanner: routedDHCPOwnerScannerV3(files.Reply), facts: routedDHCPOwnerFactsV3{binding: raw}, now: routedDHCPOwnerBootNowV3}
	r.alive = func() bool {
		return routedDHCPOwnerPIDFDAliveV3(files.RolePIDFD, int(binding.RolePID)) && routedDHCPOwnerPIDFDAliveV3(files.LeasePIDFD, int(binding.Owner.PID))
	}
	return r, nil
}

// The role becomes a subreaper before dhcpcd starts. Stop waits for its direct
// child, then kills/reaps adopted descendants. Outer cgroup drainage remains
// mandatory after abnormal role death; a missing stop acknowledgment is failure.
func routedDHCPOwnerDrainV3() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		var status unix.WaitStatus
		for {
			pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
			if errors.Is(err, unix.ECHILD) {
				return nil
			}
			if err != nil && !errors.Is(err, unix.EINTR) {
				return ErrUnavailable
			}
			if pid == 0 {
				break
			}
		}
		// No arbitrary PID is accepted: only this role's kernel-listed children.
		tasks, err := os.ReadDir("/proc/self/task")
		if err != nil || len(tasks) > 128 {
			return ErrUnavailable
		}
		for _, task := range tasks {
			tid, err := strconv.Atoi(task.Name())
			if err != nil || tid <= 0 {
				return ErrIdentity
			}
			raw, err := routedDHCPOwnerReadV3(fmt.Sprintf("/proc/self/task/%d/children", tid), 8192)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return ErrUnavailable
			}
			for _, word := range strings.Fields(string(raw)) {
				pid, err := strconv.Atoi(word)
				if err != nil || pid <= 1 {
					return ErrIdentity
				}
				fd, err := unix.PidfdOpen(pid, 0)
				if errors.Is(err, unix.ESRCH) {
					continue
				}
				if err != nil {
					return ErrUnavailable
				}
				if fd < 0 || fd > math.MaxInt32 {
					_ = unix.Close(fd)
					return ErrIdentity
				}
				poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				if n, e := unix.Poll(poll, 0); e == nil && n > 0 && poll[0].Revents&unix.POLLIN != 0 {
					_ = unix.Close(fd)
					continue // Reap this already exited child on the next iteration.
				}
				_, parent, e := routedDHCPOwnerProcessV3(pid)
				if e == nil && parent == os.Getpid() {
					e = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
				} else {
					e = ErrIdentity
				}
				_ = unix.Close(fd)
				if e != nil && !errors.Is(e, unix.ESRCH) {
					return ErrUnavailable
				}
			}
		}
		select {
		case <-ctx.Done():
			return ErrUnavailable
		case <-time.After(10 * time.Millisecond):
		}
	}
}

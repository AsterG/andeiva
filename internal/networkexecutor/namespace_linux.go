package networkexecutor

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var owners = struct {
	sync.Mutex
	ids map[uint64]bool
}{ids: map[uint64]bool{}}

// New duplicates a trusted open namespace descriptor; no caller path is opened.
// The privileged supervisor must start in the host namespace, own this lab
// namespace exclusively and retain its recovery lifetime until Restore finishes.
// Neither HTTP handlers nor untrusted IPC may construct this capability.
func New(lifetime context.Context, namespace *os.File) (*Executor, error) {
	if lifetime == nil || namespace == nil || os.Geteuid() != 0 {
		return nil, ErrScope
	}
	if err := lifetime.Err(); err != nil {
		return nil, err
	}
	host, err := os.Open("/proc/1/ns/net")
	if err != nil {
		return nil, ErrScope
	}
	defer host.Close()
	return NewWithHost(lifetime, namespace, host)
}

// NewWithHost accepts a host namespace capability opened by the trusted service
// manager before privilege restriction. That provenance cannot be inferred from
// an inode: callers must never accept this descriptor from HTTP or untrusted IPC.
// Both caller descriptors are duplicated; closing them does not revoke the pins.
// The host must equal this supervisor's current network namespace, and the target
// must be distinct. No additional privilege or caller-controlled path is needed.
func NewWithHost(lifetime context.Context, namespace, host *os.File) (*Executor, error) {
	if lifetime == nil || namespace == nil || host == nil || os.Geteuid() != 0 {
		return nil, ErrScope
	}
	if err := lifetime.Err(); err != nil {
		return nil, err
	}
	pin, id, err := pinNamespace(namespace)
	if err != nil {
		return nil, err
	}
	ok := false
	var hostPin *os.File
	defer func() {
		if !ok {
			_ = pin.Close()
			if hostPin != nil {
				_ = hostPin.Close()
			}
		}
	}()
	var hostID uint64
	hostPin, hostID, err = pinNamespace(host)
	if err != nil {
		return nil, err
	}
	self, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, ErrScope
	}
	selfID, err := namespaceID(int(self.Fd()))
	_ = self.Close()
	if err != nil || !validNamespaceBinding(id, hostID, selfID) {
		return nil, ErrScope
	}
	for _, path := range []string{"/usr/bin/nsenter", "/usr/bin/ip"} {
		if !trustedExecutable(path) {
			return nil, ErrScope
		}
	}
	owners.Lock()
	if owners.ids[id] {
		owners.Unlock()
		return nil, ErrBusy
	}
	owners.ids[id] = true
	owners.Unlock()
	e := &Executor{lifetime: lifetime}
	e.release = func() error {
		err := errors.Join(pin.Close(), hostPin.Close())
		owners.Lock()
		delete(owners.ids, id)
		owners.Unlock()
		return err
	}
	e.run = func(ctx context.Context, op operation) ([]byte, error) {
		current, err := namespaceID(int(pin.Fd()))
		if err != nil || current != id {
			return nil, ErrScope
		}
		anchor, err := namespaceID(int(hostPin.Fd()))
		if err != nil || anchor != hostID || current == anchor {
			return nil, ErrScope
		}
		if !trustedExecutable("/usr/bin/nsenter") || !trustedExecutable("/usr/bin/ip") {
			return nil, ErrScope
		}
		cmd, err := namespaceCommand(ctx, pin, op)
		if err != nil {
			return nil, err
		}
		output := &limitedBuffer{}
		stderr := &limitedBuffer{}
		cmd.Stdout = output
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrCommand
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if output.exceeded || stderr.exceeded {
			return nil, ErrCommand
		}
		return output.data, nil
	}
	ok = true
	return e, nil
}

func validNamespaceBinding(target, host, self uint64) bool {
	return target != 0 && host != 0 && self == host && target != host
}

// NewInOwnedNamespace runs only inside the manager's retained non-host namespace.
// It needs NET_ADMIN, never SYS_ADMIN or nsenter. NewWithHost remains the separate
// host-supervisor constructor. Caller pins are duplicated and never passed to ip.
func NewInOwnedNamespace(lifetime context.Context, target, host *os.File, expected OwnedNamespaceIdentity) (*Executor, error) {
	return newInOwnedNamespace(lifetime, target, host, expected, 0)
}

// NewInOwnedNamespaceWithReader adds exactly the dedicated read-only storage
// group pinned by trusted supervisor assembly. It grants no new capability and
// does not relax NewInOwnedNamespace's legacy supplementary-group contract.
// The caller must validate readerGID against the selected directory profiles;
// neither HTTP nor helper requests may choose this identity.
func NewInOwnedNamespaceWithReader(lifetime context.Context, target, host *os.File, expected OwnedNamespaceIdentity, readerGID uint32) (*Executor, error) {
	if readerGID == 0 || readerGID == ^uint32(0) || readerGID == expected.GID {
		return nil, ErrScope
	}
	return newInOwnedNamespace(lifetime, target, host, expected, readerGID)
}

func newInOwnedNamespace(lifetime context.Context, target, host *os.File, expected OwnedNamespaceIdentity, readerGID uint32) (*Executor, error) {
	if lifetime == nil || target == nil || host == nil || !validOwnedIdentity(expected) {
		return nil, ErrScope
	}
	if err := lifetime.Err(); err != nil {
		return nil, err
	}
	pin, id, err := pinNamespace(target)
	if err != nil {
		return nil, err
	}
	hostPin, hostID, err := pinNamespace(host)
	if err != nil {
		_ = pin.Close()
		return nil, err
	}
	guard := func() error {
		if id != expected.Namespace || hostID != expected.Host || verifyOwnedNamespaceWithReader(pin, hostPin, expected, readerGID) != nil || !trustedExecutable("/usr/bin/ip") {
			return ErrScope
		}
		return nil
	}
	if err := guard(); err != nil {
		_ = pin.Close()
		_ = hostPin.Close()
		return nil, err
	}
	owners.Lock()
	if owners.ids[id] {
		owners.Unlock()
		_ = pin.Close()
		_ = hostPin.Close()
		return nil, ErrBusy
	}
	owners.ids[id] = true
	owners.Unlock()
	identity := expected
	e := &Executor{lifetime: lifetime, identity: &identity}
	e.release = func() error {
		err := errors.Join(pin.Close(), hostPin.Close())
		owners.Lock()
		delete(owners.ids, id)
		owners.Unlock()
		return err
	}
	e.run = func(ctx context.Context, op operation) ([]byte, error) {
		// Pin guard and exec to the same OS thread; no setns is performed here.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if guard() != nil {
			return nil, ErrScope
		}
		cmd, err := ownedNamespaceCommand(ctx, op)
		if err != nil {
			return nil, err
		}
		output, diagnostic := &limitedBuffer{}, &limitedBuffer{}
		cmd.Stdout, cmd.Stderr = output, diagnostic
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrCommand
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if output.exceeded || diagnostic.exceeded {
			return nil, ErrCommand
		}
		return output.data, nil
	}
	return e, nil
}

func validOwnedIdentity(want OwnedNamespaceIdentity) bool {
	if want.UID == 0 || want.GID == 0 || want.Namespace == 0 || want.Host == 0 || want.Namespace == want.Host || len(want.RunID) != 32 || len(want.BootID) != 36 {
		return false
	}
	if want.BootID[8] != '-' || want.BootID[13] != '-' || want.BootID[18] != '-' || want.BootID[23] != '-' {
		return false
	}
	for _, value := range []string{want.RunID, strings.ReplaceAll(want.BootID, "-", "")} {
		if value != strings.ToLower(value) {
			return false
		}
		if _, err := hex.DecodeString(value); err != nil {
			return false
		}
	}
	return len(strings.ReplaceAll(want.BootID, "-", "")) == 32
}

func verifyOwnedNamespace(target, host *os.File, want OwnedNamespaceIdentity) error {
	return verifyOwnedNamespaceWithReader(target, host, want, 0)
}

func verifyOwnedNamespaceWithReader(target, host *os.File, want OwnedNamespaceIdentity, readerGID uint32) error {
	if !validOwnedIdentity(want) || target == nil || host == nil {
		return ErrScope
	}
	targetID, err := namespaceID(int(target.Fd()))
	if err != nil || targetID != want.Namespace {
		return ErrScope
	}
	hostID, err := namespaceID(int(host.Fd()))
	if err != nil || hostID != want.Host || targetID == hostID {
		return ErrScope
	}
	for _, thread := range []bool{false, true} {
		var self *os.File
		var err error
		if thread {
			self, err = os.Open("/proc/thread-self/ns/net")
		} else {
			self, err = os.Open("/proc/self/ns/net")
		}
		if err != nil {
			return ErrScope
		}
		selfID, err := namespaceID(int(self.Fd()))
		_ = self.Close()
		if err != nil || selfID != targetID {
			return ErrScope
		}
	}
	boot, err := readOwnedIdentityFile(true)
	if err != nil || string(boot) != want.BootID+"\n" {
		return ErrScope
	}
	status, err := readOwnedIdentityFile(false)
	if err != nil || ownedPrivileges(status, want.UID, want.GID) != nil {
		return ErrScope
	}
	groups, err := os.Getgroups()
	if err != nil {
		return ErrScope
	}
	return ownedSupplementaryGroups(groups, want.GID, readerGID)
}

func ownedSupplementaryGroups(groups []int, primary, reader uint32) error {
	if primary == 0 || reader == ^uint32(0) || (reader != 0 && reader == primary) {
		return ErrScope
	}
	found := reader == 0
	for _, group := range groups {
		if group < 0 || (uint64(group) != uint64(primary) && (reader == 0 || uint64(group) != uint64(reader))) {
			return ErrScope
		}
		found = found || uint64(group) == uint64(reader)
	}
	if !found {
		return ErrScope
	}
	return nil
}

func readOwnedIdentityFile(boot bool) ([]byte, error) {
	var f *os.File
	var err error
	var limit int64 = 64 << 10
	if boot {
		f, err = os.Open("/proc/sys/kernel/random/boot_id")
		limit = 128
	} else {
		f, err = os.Open("/proc/thread-self/status")
	}
	if err != nil {
		return nil, ErrScope
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, ErrScope
	}
	return data, nil
}

func ownedPrivileges(status []byte, uid, gid uint32) error {
	if uid == 0 || gid == 0 || len(status) > 64<<10 {
		return ErrScope
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || (key != "Uid" && key != "Gid" && key != "NoNewPrivs" && key != "CapInh" && key != "CapPrm" && key != "CapEff" && key != "CapBnd" && key != "CapAmb") {
			continue
		}
		if seen[key] {
			return ErrScope
		}
		seen[key] = true
		fields := strings.Fields(value)
		switch key {
		case "Uid", "Gid":
			want := uid
			if key == "Gid" {
				want = gid
			}
			if len(fields) != 4 {
				return ErrScope
			}
			for _, field := range fields {
				id, err := strconv.ParseUint(field, 10, 32)
				if err != nil || id != uint64(want) {
					return ErrScope
				}
			}
		case "NoNewPrivs":
			if len(fields) != 1 || fields[0] != "1" {
				return ErrScope
			}
		default:
			if len(fields) != 1 || len(fields[0]) != 16 {
				return ErrScope
			}
			mask, err := strconv.ParseUint(fields[0], 16, 64)
			if err != nil || mask != uint64(1)<<12 {
				return ErrScope
			}
		}
	}
	if len(seen) != 8 {
		return ErrScope
	}
	return nil
}

func ownedNamespaceCommand(ctx context.Context, op operation) (*exec.Cmd, error) {
	args, err := arguments(op)
	if err != nil || ctx == nil {
		return nil, ErrScope
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/ip", args...) // #nosec G204 -- Fixed executable, private validated operations, verified inherited namespace.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return cmd, nil
}

func pinNamespace(source *os.File) (*os.File, uint64, error) {
	if source == nil {
		return nil, 0, ErrScope
	}
	fd, err := unix.FcntlInt(source.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, 0, ErrScope
	}
	pin := os.NewFile(uintptr(fd), "andeiva-network-namespace")
	id, err := namespaceID(fd)
	if err != nil {
		_ = pin.Close()
		return nil, 0, err
	}
	return pin, id, nil
}

// namespaceCommand only constructs the allowlisted invocation. The owner checks
// the namespace pin and trusted binaries immediately before constructing it.
func namespaceCommand(ctx context.Context, pin *os.File, op operation) (*exec.Cmd, error) {
	args, err := arguments(op)
	if err != nil || pin == nil {
		return nil, ErrScope
	}
	argv := append([]string{"--net=/proc/self/fd/3", "--", "/usr/bin/ip"}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", argv...) // #nosec G204 -- Fixed executable, private typed operation, pinned non-host namespace FD.
	cmd.ExtraFiles = []*os.File{pin}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return cmd, nil
}
func namespaceID(fd int) (uint64, error) {
	var fs unix.Statfs_t
	var st unix.Stat_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC || unix.Fstat(fd, &st) != nil {
		return 0, ErrScope
	}
	kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWNET {
		return 0, ErrScope
	}
	return st.Ino, nil
}
func trustedExecutable(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return false
	}
	for dir := filepath.Dir(resolved); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		if dir == "/" {
			return true
		}
	}
}

type limitedBuffer struct {
	data     []byte
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > maxOutput-len(b.data) {
		b.exceeded = true
		return 0, io.ErrShortWrite
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

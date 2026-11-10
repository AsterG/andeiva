package localtransport

import (
	"bytes"
	"context"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const nftPath = "/usr/sbin/nft"
const netAdminMask = uint64(1) << 12

type identity struct {
	uid, gid        int
	namespace, host uint64
}

// New must run in the retained gateway namespace with its descriptor at FD3.
// Expected identities come from the trusted supervisor, not a public request.
func New(namespace, host uint64) (*Transport, error) {
	if namespace == 0 || host == 0 || namespace == host || os.Getuid() <= 0 || os.Getgid() <= 0 {
		return nil, ErrIdentity
	}
	want := identity{os.Getuid(), os.Getgid(), namespace, host}
	guard := func() error { return verifyIdentity(want) }
	if guard() != nil || trustedNft() != nil {
		return nil, ErrIdentity
	}
	return &Transport{guard: guard, execute: execute}, nil
}

func verifyIdentity(want identity) error {
	if os.Getuid() <= 0 || os.Getgid() <= 0 || os.Getuid() != want.uid || os.Getgid() != want.gid {
		return ErrIdentity
	}
	if err := verifyNamespace(want.namespace, want.host); err != nil {
		return err
	}
	status, err := os.Open("/proc/self/status")
	if err != nil {
		return ErrIdentity
	}
	defer status.Close()
	data, err := io.ReadAll(io.LimitReader(status, 64<<10+1))
	if err != nil || len(data) > 64<<10 || privileges(data, want.uid, want.gid) != nil {
		return ErrIdentity
	}
	return nil
}

func verifyNamespace(expected, host uint64) error {
	// Check the inherited descriptor before opening any file: otherwise an
	// open could reuse a missing FD3 and falsely turn the current namespace into
	// the supervisor's retained namespace pin.
	pinned, err := namespaceInode(3)
	if err != nil || expected == 0 || host == 0 || pinned != expected || pinned == host {
		return ErrIdentity
	}
	retained, err := syscall.Dup(3)
	if err != nil {
		return ErrIdentity
	}
	syscall.CloseOnExec(retained)
	defer syscall.Close(retained)
	pinned, err = namespaceInode(retained)
	if err != nil || pinned != expected {
		return ErrIdentity
	}
	self, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return ErrIdentity
	}
	defer self.Close()
	current, err := namespaceInode(int(self.Fd()))
	if err != nil || current != expected || current == host {
		return ErrIdentity
	}
	if pinned != current {
		return ErrIdentity
	}
	return nil
}

func namespaceInode(fd int) (uint64, error) {
	var fs syscall.Statfs_t
	var st syscall.Stat_t
	if fd < 0 || syscall.Fstatfs(fd, &fs) != nil || fs.Type != 0x6e736673 || syscall.Fstat(fd, &st) != nil || st.Ino == 0 {
		return 0, ErrIdentity
	}
	kind, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0xb703, 0)
	if errno != 0 || kind != syscall.CLONE_NEWNET {
		return 0, ErrIdentity
	}
	return st.Ino, nil
}

func privileges(data []byte, uid, gid int) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if key != "Uid" && key != "Gid" && key != "NoNewPrivs" && key != "CapInh" && key != "CapPrm" && key != "CapEff" && key != "CapBnd" && key != "CapAmb" {
			continue
		}
		if seen[key] {
			return ErrIdentity
		}
		seen[key] = true
		fields := strings.Fields(value)
		switch key {
		case "Uid", "Gid":
			if len(fields) != 4 {
				return ErrIdentity
			}
			want := uid
			if key == "Gid" {
				want = gid
			}
			for _, field := range fields {
				v, e := strconv.ParseInt(field, 10, 64)
				if e != nil || v <= 0 || v > math.MaxUint32 || v != int64(want) || want <= 0 {
					return ErrIdentity
				}
			}
		case "NoNewPrivs":
			if len(fields) != 1 || fields[0] != "1" {
				return ErrIdentity
			}
		default:
			if len(fields) != 1 || len(fields[0]) != 16 {
				return ErrIdentity
			}
			v, e := strconv.ParseUint(fields[0], 16, 64)
			if e != nil || v != netAdminMask {
				return ErrIdentity
			}
		}
	}
	if len(seen) != 8 {
		return ErrIdentity
	}
	return nil
}

func trustedNft() error {
	resolved, err := filepath.EvalSymlinks(nftPath)
	if err != nil || !filepath.IsAbs(resolved) {
		return ErrIdentity
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return ErrIdentity
	}
	for dir := filepath.Dir(resolved); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return ErrIdentity
		}
		if dir == "/" {
			return nil
		}
	}
}

func command(ctx context.Context, op operation) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	switch op {
	case check:
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-c", "-f", "-")
	case apply:
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-f", "-")
	case listTables:
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "list", "tables")
	case listTable:
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "list", "table", "inet", "andeiva_local")
	default:
		return nil, ErrInput
	}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 100 * time.Millisecond
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return cmd, nil
}

func execute(ctx context.Context, op operation, input []byte) ([]byte, error) {
	cmd, err := command(ctx, op)
	if err != nil {
		return nil, err
	}
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr limitedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if cmd.Run() != nil {
		return nil, ErrCommand
	}
	if stdout.failed() || stderr.failed() {
		return nil, ErrObservation
	}
	if stderr.Len() != 0 {
		return nil, ErrCommand
	}
	return stdout.Bytes(), nil
}

type limitedBuffer struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) > MaxOutput-b.buffer.Len() {
		b.overflow = true
		return 0, ErrObservation
	}
	return b.buffer.Write(p)
}
func (b *limitedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buffer.Bytes())
}
func (b *limitedBuffer) Len() int     { b.mu.Lock(); defer b.mu.Unlock(); return b.buffer.Len() }
func (b *limitedBuffer) failed() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.overflow }

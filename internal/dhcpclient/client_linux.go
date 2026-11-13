//go:build linux

package dhcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/jsoncheck"
	"golang.org/x/sys/unix"
)

const (
	HookPath     = "/usr/libexec/andeiva-dhcp-hook"
	configPath   = "/run/andeiva-dhcp/client.conf"
	clientConfig = "noipv6\nnoipv4ll\nnoconfigure\nnoup\n"
)

// Scope is trusted supervisor input. Both host namespace capabilities must be
// retained before isolation; accepting arbitrary caller descriptors is unsafe.
// The experimental role has its own root/privsep process and private mounts. It
// is deliberately separate from the NET_ADMIN-only firewall helper and API.
type Scope struct {
	HostNetwork, HostMount *os.File
	Interface              string
	HardwareAddress        string
	Index                  int
}

// Lease is acquisition evidence only. It authorizes neither L3 writes nor
// traffic. DeadlineBootNS is conservative and never refreshed by reading it.
type Lease struct {
	Event          Event
	Epoch          uint64
	DeadlineBootNS int64
}

type Client struct {
	mu                   sync.Mutex
	cmd                  *exec.Cmd
	lock                 *os.File
	output               *os.File
	done                 chan struct{}
	lease                Lease
	epoch                uint64
	lastGrant, lastEvent int64
	iface                string
	pid                  int
	failed               bool
	failure              string
	lastReason           string
	exitCode             int
	stopOnce             sync.Once
}

func bootNow() (int64, error) {
	var t unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t); err != nil {
		return 0, err
	}
	return t.Nano(), nil
}

// WriteHook writes one bounded record to the private inherited stdout pipe.
// dhcpcd invokes this fixed binary directly. No network, filesystem writes,
// subprocess, hostname, resolver or route changes are performed by the hook.
func WriteHook(out io.Writer) error {
	now, err := bootNow()
	if err != nil {
		return err
	}
	e, err := HookEvent(os.Environ(), now)
	if err != nil {
		_, _ = io.WriteString(out, "{}\n")
		return err
	}
	b, err := json.Marshal(e)
	if err != nil || len(b)+1 > MaxEventBytes {
		return ErrEvent
	}
	_, err = out.Write(append(b, '\n'))
	return err
}

// StartIsolated starts the fixed Debian dhcpcd in acquisition-only mode. This is
// an opt-in laboratory profile, not installed-runtime authority. The outer unit
// must own the entire cgroup (KillMode=control-group) for supervisor death, since
// dhcpcd's privilege-separated descendants have their own lifetimes.
func StartIsolated(ctx context.Context, scope Scope) (*Client, error) {
	if ctx == nil || ctx.Err() != nil || verifyScope(scope) != nil {
		return nil, ErrScope
	}
	fd, err := unix.Open("/run/andeiva-dhcp/owner.lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrScope
	}
	lock := os.NewFile(uintptr(fd), "dhcp-owner")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&07777 != 0600 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		lock.Close()
		return nil, ErrScope
	}
	failed := true
	defer func() {
		if failed {
			lock.Close()
		}
	}()
	// Configuration cannot import host defaults, hooks or paths.
	if err := fixedConfig(); err != nil {
		return nil, err
	}
	for _, path := range []string{"/usr/sbin/dhcpcd", HookPath} {
		if err := trustedFile(path, true); err != nil {
			return nil, err
		}
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	now, err := bootNow()
	if err != nil {
		r.Close()
		w.Close()
		return nil, err
	}
	c := &Client{lock: lock, output: r, done: make(chan struct{}), iface: scope.Interface, lastGrant: now}
	cmd := exec.Command("/usr/sbin/dhcpcd", "-4", "-B", "-L", "--noconfigure", "--nodev", "-f", configPath, "-c", HookPath, scope.Interface)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	cmd.Stdout = w
	// No raw lease/options or engine diagnostics escape through public output.
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	c.cmd = cmd
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := verifyScope(scope); err != nil {
			started <- err
			return
		}
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		c.pid = cmd.Process.Pid
		started <- nil
		// Keep the leader unreaped while signalling its owned process group;
		// otherwise a recycled numeric PID could identify an unrelated group.
		var info unix.Siginfo
		var waitErr error
		for {
			waitErr = unix.Waitid(unix.P_PID, c.pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
			if !errors.Is(waitErr, unix.EINTR) {
				break
			}
		}
		if waitErr == nil {
			_ = unix.Kill(-c.pid, unix.SIGKILL)
		} else {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		c.mu.Lock()
		c.failed = true
		c.lease = Lease{}
		if c.failure == "" {
			c.failure = "owner_exit"
		}
		if cmd.ProcessState != nil {
			c.exitCode = cmd.ProcessState.ExitCode()
		}
		c.mu.Unlock()
		_ = r.Close()
		close(c.done)
	}()
	err = <-started
	_ = w.Close()
	if err != nil {
		r.Close()
		return nil, err
	}
	failed = false
	go c.readEvents()
	go func() {
		select {
		case <-ctx.Done():
			c.Stop()
		case <-c.done:
		}
	}()
	return c, nil
}

func (c *Client) readEvents() {
	s := bufio.NewScanner(c.output)
	s.Buffer(make([]byte, 512), MaxEventBytes)
	for s.Scan() {
		e, err := decodeEvent(s.Bytes())
		if err != nil {
			c.failAt("event_decode")
			_ = c.cmd.Process.Kill()
			return
		}
		now, err := bootNow()
		if err != nil || c.accept(e, now) != nil {
			c.failAt("event_scope")
			_ = c.cmd.Process.Kill()
			return
		}
	}
	c.failAt("event_channel_closed")
	_ = c.cmd.Process.Kill()
}

func decodeEvent(b []byte) (Event, error) {
	var e Event
	if len(b) == 0 || len(b) >= MaxEventBytes || !jsoncheck.UniqueControlFields(b) {
		return e, ErrEvent
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil || d.Decode(new(any)) != io.EOF || e.validate() != nil {
		return Event{}, ErrEvent
	}
	return e, nil
}

func (c *Client) invalidate() { c.failAt("stopped") }
func (c *Client) failAt(stage string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failed = true
	c.lease = Lease{}
	if c.failure == "" {
		c.failure = stage
	}
}

func (c *Client) accept(e Event, now int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed || e.Interface != c.iface || e.PID != c.pid || e.BootNS <= c.lastEvent || e.BootNS > now || now-e.BootNS > int64(2*time.Second) {
		return ErrEvent
	}
	c.lastEvent = e.BootNS
	c.lastReason = e.Reason
	if granting(e.Reason) {
		// The hook does not expose the ACK acquisition clock. The previous
		// grant hook (or process start for the first) precedes this ACK. Use
		// that lower bound, never arrival+lease, which could extend validity.
		deadline := c.lastGrant + int64(e.Seconds)*int64(time.Second)
		if deadline <= now || e.BootNS < c.lastGrant {
			return ErrEvent
		}
		c.epoch++
		c.lease = Lease{Event: e, Epoch: c.epoch, DeadlineBootNS: deadline}
		c.lastGrant = e.BootNS
		return nil
	}
	switch e.Reason {
	case "CARRIER":
	default:
		c.lease = Lease{}
	}
	return nil
}

func (c *Client) Current() (Lease, error) {
	if c == nil {
		return Lease{}, ErrUnavailable
	}
	now, err := bootNow()
	if err != nil {
		return Lease{}, ErrUnavailable
	}
	return c.currentAt(now)
}
func (c *Client) currentAt(now int64) (Lease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed || c.lease.DeadlineBootNS <= now || c.lease.DeadlineBootNS == 0 {
		return Lease{}, ErrUnavailable
	}
	l := c.lease
	l.Event.DNS = append([]string(nil), l.Event.DNS...)
	return l, nil
}

// Renew requests a fresh renewal through dhcpcd 10.1.0's SIGUSR1 operation.
// SIGALRM releases and exits; it must never be used for renewal.
func (c *Client) Renew() error { return c.signal(syscall.SIGUSR1) }

// Rebind reloads the fixed configuration and restarts acquisition. Its
// RECONFIGURE notification revokes evidence until a new confirmed grant.
// Both operations signal only the retained child, never a global pidfile.
func (c *Client) Rebind() error {
	return c.signal(syscall.SIGHUP)
}

func (c *Client) signal(signal syscall.Signal) error {
	if c == nil {
		return ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed {
		return ErrUnavailable
	}
	return c.cmd.Process.Signal(signal)
}

// Stop invalidates evidence before stopping the owner. It cannot restore a
// previous DHCP lease; restart must obtain fresh confirmed acquisition evidence.
func (c *Client) Stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		c.invalidate()
		_ = c.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-c.done:
		case <-time.After(2 * time.Second):
			_ = c.cmd.Process.Kill()
			<-c.done
		}
		_ = c.lock.Close()
	})
}

func fixedConfig() error {
	fd, err := unix.Open(configPath, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err == nil {
		f := os.NewFile(uintptr(fd), "dhcp-config")
		_, werr := io.WriteString(f, clientConfig)
		serr := f.Sync()
		cerr := f.Close()
		if errors.Join(werr, serr, cerr) != nil {
			return ErrScope
		}
	} else if !errors.Is(err, unix.EEXIST) {
		return ErrScope
	}
	if trustedFile(configPath, false) != nil {
		return ErrScope
	}
	f, err := os.Open(configPath)
	if err != nil {
		return ErrScope
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(len(clientConfig)+1)))
	if err != nil || string(b) != clientConfig {
		return ErrScope
	}
	return nil
}

func trustedFile(path string, executable bool) error {
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Mode&06000 != 0 || executable && st.Mode&0111 == 0 {
		return ErrScope
	}
	return nil
}

func differentNamespace(host *os.File, kind int, self string) error {
	if host == nil {
		return ErrScope
	}
	k, err := unix.IoctlRetInt(int(host.Fd()), unix.NS_GET_NSTYPE)
	var h, s unix.Stat_t
	if err != nil || k != kind || unix.Fstat(int(host.Fd()), &h) != nil || unix.Stat(self, &s) != nil || h.Ino == s.Ino {
		return ErrScope
	}
	return nil
}

func verifyScope(s Scope) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || !interfaceName(s.Interface) || s.Index <= 0 || differentNamespace(s.HostNetwork, unix.CLONE_NEWNET, "/proc/self/ns/net") != nil || differentNamespace(s.HostNetwork, unix.CLONE_NEWNET, "/proc/thread-self/ns/net") != nil || differentNamespace(s.HostMount, unix.CLONE_NEWNS, "/proc/self/ns/mnt") != nil || differentNamespace(s.HostMount, unix.CLONE_NEWNS, "/proc/thread-self/ns/mnt") != nil {
		return ErrScope
	}
	for _, kind := range []string{"net", "mnt"} {
		var leader, thread unix.Stat_t
		if unix.Stat("/proc/self/ns/"+kind, &leader) != nil || unix.Stat("/proc/thread-self/ns/"+kind, &thread) != nil || leader.Ino != thread.Ino {
			return ErrScope
		}
	}
	i, err := net.InterfaceByName(s.Interface)
	if err != nil || i.Index != s.Index || i.HardwareAddr.String() != s.HardwareAddress || i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
		return ErrScope
	}
	// Dedicated tmpfs roots ensure neither pid/lease state nor hooks can touch
	// host dhcpcd paths. Shared/slave mount propagation is forbidden.
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return ErrScope
	}
	defer f.Close()
	want := map[string]bool{"/run/dhcpcd": false, "/var/lib/dhcpcd": false, "/run/andeiva-dhcp": false}
	scan := bufio.NewScanner(io.LimitReader(f, 1<<20))
	scan.Buffer(make([]byte, 4096), 64<<10)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) < 10 {
			return ErrScope
		}
		if _, exists := want[fields[4]]; !exists {
			continue
		}
		if fields[3] != "/" || fields[6] != "-" || fields[7] != "tmpfs" || want[fields[4]] {
			return ErrScope
		}
		var st unix.Stat_t
		if unix.Lstat(fields[4], &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 {
			return ErrScope
		}
		want[fields[4]] = true
	}
	if scan.Err() != nil {
		return ErrScope
	}
	for _, found := range want {
		if !found {
			return ErrScope
		}
	}
	return nil
}

// PID is diagnostic identity for the private laboratory, not API authorization.
func (c *Client) PID() string { return strconv.Itoa(c.pid) }

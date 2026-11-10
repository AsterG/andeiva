package localobserve

import (
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type Collector struct {
	mu          sync.Mutex
	root        *os.Root
	expected    Expected
	pid, parent int
	start       uint64
	process     *os.Process
}

// New binds a directly owned unprivileged child. It retains the proc directory;
// subsequent observations never reopen a caller-supplied PID or pathname.
func New(child *os.Process, expected Expected) (*Collector, error) {
	if runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return nil, ErrPlatform
	}
	if child == nil || child.Pid <= 1 || expected.UID == 0 || expected.GID == 0 || expected.Namespace == 0 || expected.Namespace == expected.HostNamespace || expected.Generation == 0 || !canonicalID(expected.RunID) || !canonicalID(expected.Instance) {
		return nil, ErrIdentity
	}
	// Signal zero delivers no signal. The retained process handle adds a
	// liveness check without trusting a numeric PID alone.
	if child.Signal(syscall.Signal(0)) != nil {
		return nil, ErrIdentity
	}
	host, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return nil, ErrIdentity
	}
	hostID, err := namespaceID(host)
	if err != nil || hostID != expected.HostNamespace {
		return nil, ErrIdentity
	}
	proc, err := os.OpenRoot("/proc")
	if err != nil {
		return nil, ErrIdentity
	}
	defer proc.Close()
	pinned, err := proc.OpenRoot(strconv.Itoa(child.Pid))
	if err != nil {
		return nil, ErrIdentity
	}
	c := &Collector{root: pinned, expected: expected, pid: child.Pid, parent: os.Getpid(), process: child}
	identity, err := c.readIdentity()
	if err != nil {
		_ = pinned.Close()
		return nil, err
	}
	c.start = identity.start
	if err := c.validateIdentity(identity); err != nil {
		_ = pinned.Close()
		return nil, err
	}
	again, err := c.readIdentity()
	if err != nil || again != identity || child.Signal(syscall.Signal(0)) != nil {
		_ = pinned.Close()
		return nil, ErrUnstable
	}
	return c, nil
}

func (c *Collector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.root == nil {
		return nil
	}
	err := c.root.Close()
	c.root = nil
	return err
}

// Observe rejects inconsistent multiple reads rather than publishing guesses.
// The caller must reject foreign and unexpected/wildcard/mapped listeners before
// confirming a service revision. Successful collection is not admission.
func (c *Collector) Observe() (Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.root == nil {
		return Snapshot{}, ErrClosed
	}
	if c.process == nil || c.process.Signal(syscall.Signal(0)) != nil {
		return Snapshot{}, ErrIdentity
	}
	first, err := c.readCapture()
	if err != nil {
		return Snapshot{}, err
	}
	second, err := c.readCapture()
	if err != nil {
		return Snapshot{}, err
	}
	if c.process.Signal(syscall.Signal(0)) != nil {
		return Snapshot{}, ErrIdentity
	}
	return verifyStable(first, second, c.expected, c.start)
}

func (c *Collector) readFile(name string, max int) ([]byte, error) {
	file, err := c.root.Open(name)
	if err != nil {
		return nil, ErrIdentity
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrMalformed
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil || len(data) > max {
		return nil, ErrMalformed
	}
	return data, nil
}

func (c *Collector) readIdentity() (processIdentity, error) {
	stat, err := c.readFile("stat", MaxIdentityBytes)
	if err != nil {
		return processIdentity{}, err
	}
	pid, parent, start, err := parseStat(stat)
	if err != nil {
		return processIdentity{}, ErrIdentity
	}
	status, err := c.readFile("status", MaxIdentityBytes)
	if err != nil {
		return processIdentity{}, err
	}
	uid, gid, statusParent, err := parseStatus(status)
	if err != nil || statusParent != parent {
		return processIdentity{}, ErrIdentity
	}
	// Read only the fixed namespace link text; never follow it or an FD symlink.
	link, err := c.root.Readlink("ns/net")
	if err != nil {
		return processIdentity{}, ErrIdentity
	}
	namespace, err := namespaceID(link)
	if err != nil {
		return processIdentity{}, ErrIdentity
	}
	return processIdentity{pid: pid, parent: parent, start: start, uid: uid, gid: gid, namespace: namespace}, nil
}

func (c *Collector) validateIdentity(identity processIdentity) error {
	if identity.pid != c.pid || identity.parent != c.parent || identity.start != c.start || identity.namespace != c.expected.Namespace {
		return ErrIdentity
	}
	for _, uid := range identity.uid {
		if uid != c.expected.UID {
			return ErrIdentity
		}
	}
	for _, gid := range identity.gid {
		if gid != c.expected.GID {
			return ErrIdentity
		}
	}
	return nil
}

func (c *Collector) readCapture() (capture, error) {
	identity, err := c.readIdentity()
	if err != nil {
		return capture{}, err
	}
	if err := c.validateIdentity(identity); err != nil {
		return capture{}, err
	}
	result := capture{identity: identity, sockets: []Socket{}, fds: []socketFD{}}
	for _, table := range []struct{ name, protocol, family string }{{"net/tcp", "tcp", "ipv4"}, {"net/tcp6", "tcp", "ipv6"}, {"net/udp", "udp", "ipv4"}, {"net/udp6", "udp", "ipv6"}} {
		data, err := c.readFile(table.name, MaxTableBytes)
		if err != nil {
			return capture{}, err
		}
		sockets, err := parseTable(data, table.protocol, table.family)
		if err != nil {
			return capture{}, err
		}
		result.sockets = append(result.sockets, sockets...)
		if len(result.sockets) > MaxRows {
			return capture{}, ErrMalformed
		}
	}
	result.fds, err = c.readFDs()
	if err != nil {
		return capture{}, err
	}
	after, err := c.readIdentity()
	if err != nil {
		return capture{}, err
	}
	if after != identity {
		return capture{}, ErrUnstable
	}
	sortCapture(&result)
	return result, nil
}

func (c *Collector) readFDs() ([]socketFD, error) {
	dir, err := c.root.Open("fd")
	if err != nil {
		return nil, ErrIdentity
	}
	defer dir.Close()
	entries, err := dir.ReadDir(MaxFDs + 1)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > MaxFDs {
		return nil, ErrMalformed
	}
	return readSocketFDs(entries, c.root.Readlink)
}

func readSocketFDs(entries []os.DirEntry, readlink func(string) (string, error)) ([]socketFD, error) {
	result := []socketFD{}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd < 0 || fd > 1<<20 || strconv.Itoa(fd) != entry.Name() || entry.Type()&os.ModeSymlink == 0 {
			return nil, ErrMalformed
		}
		link, err := readlink("fd/" + entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			// A connection may close after enumeration. Missing descriptors never
			// prove ownership: retained listener rows remain foreign unless another
			// descriptor owns their inode, and both captures must agree.
			continue
		}
		if err != nil {
			return nil, ErrUnstable
		}
		if len(link) > 4096 {
			return nil, ErrMalformed
		}
		if !strings.HasPrefix(link, "socket:") {
			continue
		}
		inode, err := bracketID(link, "socket:[")
		if err != nil {
			return nil, err
		}
		result = append(result, socketFD{fd, inode})
	}
	return result, nil
}

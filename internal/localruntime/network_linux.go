//go:build linux

package localruntime

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func openAssets(path string) (*os.Root, error) {
	r, e := os.OpenRoot(path)
	if e != nil {
		return nil, ErrUnavailable
	}
	count := 0
	var size int64
	e = fs.WalkDir(r.FS(), ".", func(name string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		count++
		if count > 512 || d.Type()&os.ModeSymlink != 0 {
			return ErrUnavailable
		}
		i, e := d.Info()
		if e != nil {
			return e
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 0 || i.Mode().Perm()&0022 != 0 || (!i.IsDir() && !i.Mode().IsRegular()) {
			return ErrUnavailable
		}
		size += i.Size()
		if size > 64<<20 {
			return ErrUnavailable
		}
		return nil
	})
	if e == nil {
		info, err := r.Stat("index.html")
		if err != nil || !info.Mode().IsRegular() {
			e = ErrUnavailable
		}
	}
	if e != nil {
		_ = r.Close()
		return nil, ErrUnavailable
	}
	return r, nil
}
func bindRecovery(ctx context.Context, c Config) (*net.TCPListener, *net.TCPListener, error) {
	iface, e := net.InterfaceByName(c.LANInterface)
	if e != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return nil, nil, ErrUnavailable
	}
	addresses, e := iface.Addrs()
	if e != nil {
		return nil, nil, e
	}
	found := false
	for _, a := range addresses {
		p, e := netip.ParsePrefix(a.String())
		if e == nil && p.Addr().String() == c.LANAddress {
			found = true
		}
	}
	if !found {
		return nil, nil, ErrUnavailable
	}
	var lc net.ListenConfig
	lc.Control = func(_, _ string, raw syscall.RawConn) error {
		var err error
		if e := raw.Control(func(fd uintptr) {
			if fd > 2147483647 {
				err = ErrUnavailable
				return
			}
			err = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, c.LANInterface)
		}); e != nil {
			return e
		}
		return err
	}
	lan, e := lc.Listen(ctx, "tcp4", net.JoinHostPort(c.LANAddress, strconv.Itoa(RecoveryPort)))
	if e != nil {
		return nil, nil, ErrUnavailable
	}
	loop, e := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(RecoveryPort))
	if e != nil {
		_ = lan.Close()
		return nil, nil, ErrUnavailable
	}
	l, ok := lan.(*net.TCPListener)
	p, pok := loop.(*net.TCPListener)
	if !ok || !pok {
		_ = lan.Close()
		_ = loop.Close()
		return nil, nil, ErrUnavailable
	}
	return l, p, nil
}

type recoveryBudget struct{ connections, requests chan struct{} }

func newRecoveryBudget() *recoveryBudget {
	return &recoveryBudget{make(chan struct{}, 16), make(chan struct{}, 8)}
}
func (b *recoveryBudget) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case b.requests <- struct{}{}:
			defer func() { <-b.requests }()
			next.ServeHTTP(w, r)
		default:
			http.Error(w, ErrUnavailable.Error(), http.StatusServiceUnavailable)
		}
	})
}

type recoveryListener struct {
	net.Listener
	allowed netip.Prefix
	budget  *recoveryBudget
}

func newRecoveryListener(l net.Listener, p netip.Prefix, b *recoveryBudget) net.Listener {
	return &recoveryListener{l, p, b}
}
func (l *recoveryListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		a, e := netip.ParseAddrPort(c.RemoteAddr().String())
		if e != nil || !l.allowed.Contains(a.Addr().Unmap()) {
			if c.Close() != nil {
				return nil, ErrUnavailable
			}
			continue
		}
		select {
		case l.budget.connections <- struct{}{}:
			return &budgetConn{Conn: c, budget: l.budget}, nil
		default:
			if c.Close() != nil {
				return nil, ErrUnavailable
			}
		}
	}
}

type budgetConn struct {
	net.Conn
	budget *recoveryBudget
	once   sync.Once
	err    error
}

func (c *budgetConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); <-c.budget.connections })
	return c.err
}
func pair() (*os.File, *os.File, error) {
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, nil, e
	}
	return os.NewFile(uintptr(fds[0]), "private-channel"), os.NewFile(uintptr(fds[1]), "private-channel"), nil
}
func writeBootstrap(v any) (*os.File, error) {
	b := encode(v)
	if len(b) > 4096 {
		return nil, ErrUnavailable
	}
	r, w, e := os.Pipe()
	if e != nil {
		return nil, e
	}
	_, e = w.Write(b)
	e = errors.Join(e, w.Close())
	if e != nil {
		_ = r.Close()
		return nil, e
	}
	return r, nil
}
func openExclusiveOutput(path string, b []byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(b) > 1<<20 {
		return ErrUnavailable
	}
	r, e := os.OpenRoot(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer r.Close()
	return writeNew(r, filepath.Base(path), b, 0, 0, 0600)
}
func rootPeer(c *net.UnixConn) bool {
	raw, e := c.SyscallConn()
	if e != nil {
		return false
	}
	valid := false
	if raw.Control(func(fd uintptr) {
		if fd > 2147483647 {
			return
		}
		p, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		valid = e == nil && p.Uid == 0
	}) != nil {
		return false
	}
	return valid
}
func boundedConn(c net.Conn) error { return c.SetDeadline(time.Now().Add(30 * time.Second)) }

//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/firewallnft"
)

type hello struct {
	Version    int    `json:"version"`
	RuntimeRun string `json:"runtime_run"`
	Run        string `json:"run,omitempty"`
	Epoch      uint64 `json:"epoch,omitempty"`
	Namespace  uint64 `json:"namespace"`
}

func peer(c *net.UnixConn, uid, gid uint32) error {
	raw, e := c.SyscallConn()
	if e != nil {
		return ErrIdentity
	}
	var cred *syscall.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) {
		cred, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if e != nil || inner != nil || cred == nil || cred.Uid != uid || cred.Gid != gid || cred.Pid <= 1 {
		return ErrIdentity
	}
	return nil
}
func socketInfo(path string, uid, gid uint32) error {
	if safeParents(path) != nil {
		return ErrIdentity
	}
	st, e := os.Lstat(path)
	if e != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0660 {
		return ErrIdentity
	}
	s := st.Sys().(*syscall.Stat_t)
	if s.Uid != uid || s.Gid != gid {
		return ErrIdentity
	}
	return nil
}
func listenPrivate(path string, uid, gid uint32) (*net.UnixListener, error) {
	if safeParents(path) != nil {
		return nil, ErrIdentity
	}
	st, e := os.Lstat(filepath.Dir(path))
	if e != nil || (st.Mode().Perm() != 0750 && st.Mode().Perm() != 0700) {
		return nil, ErrIdentity
	}
	s := st.Sys().(*syscall.Stat_t)
	if s.Uid != uid || s.Gid != gid {
		return nil, ErrIdentity
	}
	if _, e = os.Lstat(path); !os.IsNotExist(e) {
		return nil, ErrIdentity
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return nil, ErrUnavailable
	}
	l.SetUnlinkOnClose(false)
	if os.Chmod(path, 0660) != nil {
		l.Close()
		return nil, ErrStorage
	}
	return l, nil
}
func removeSocket(path string, st os.FileInfo) {
	if current, e := os.Lstat(path); e == nil && os.SameFile(st, current) {
		_ = os.Remove(path)
	}
}
func readFrame(c *net.UnixConn, r *bufio.Reader, first bool) ([]byte, error) {
	// Idle controllers consume no timer. Once a frame begins it must finish promptly.
	if !first {
		_ = c.SetReadDeadline(time.Time{})
		if _, e := r.Peek(1); e != nil {
			return nil, e
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, e := r.ReadSlice('\n')
	if e != nil || len(b) > firewallipc.MaxFrame {
		return nil, ErrUnavailable
	}
	return b, nil
}
func artifactDigest(c configpoc.Config) (string, error) {
	a, e := firewallnft.Compile(c)
	return a.Digest, e
}
func connectHelper(ctx context.Context, m Metadata, ids Identities) (*firewallipc.Client, error) {
	if socketInfo(HelperSocket, ids.HelperUID, ids.IPCGID) != nil {
		return nil, ErrIdentity
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, e := d.DialContext(ctx, "unix", HelperSocket)
	if e != nil {
		return nil, ErrUnavailable
	}
	c := conn.(*net.UnixConn)
	fail := func() (*firewallipc.Client, error) { c.Close(); return nil, ErrIdentity }
	if peer(c, ids.HelperUID, ids.IPCGID) != nil || socketInfo(HelperSocket, ids.HelperUID, ids.IPCGID) != nil {
		return fail()
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if json.NewEncoder(c).Encode(hello{Version: 1, RuntimeRun: m.RunID, Namespace: m.GatewayNamespace}) != nil {
		return fail()
	}
	r := bufio.NewReaderSize(c, firewallipc.MaxFrame)
	b, e := readFrame(c, r, true)
	var h hello
	if e != nil || firewallipc.Decode(b, &h) != nil || h.Version != 1 || h.RuntimeRun != m.RunID || !validHex(h.Run, 16) || h.Namespace != m.GatewayNamespace || h.Epoch == 0 || h.Epoch > 0xffffffff || r.Buffered() != 0 {
		return fail()
	}
	_ = c.SetDeadline(time.Time{})
	client, e := firewallipc.New(c, c, h.Run, h.Epoch<<32, h.Namespace, artifactDigest)
	if e != nil {
		return fail()
	}
	return client, nil
}

// serveController retains Session and guardian across API disconnects. Only one
// authenticated controller exists; a new epoch cannot inherit a recovery barrier.
func serveController(ctx context.Context, l *net.UnixListener, m Metadata, ids Identities, s *Session) error {
	var mu sync.Mutex
	var active *net.UnixConn
	var epoch uint64
	var workers sync.WaitGroup
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
			mu.Lock()
			if active != nil {
				active.Close()
			}
			mu.Unlock()
		case <-done:
		}
	}()
	defer workers.Wait()
	defer func() {
		mu.Lock()
		if active != nil {
			active.Close()
		}
		mu.Unlock()
	}()
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrUnavailable
		}
		if peer(c, ids.APIUID, ids.APIGID) != nil {
			c.Close()
			continue
		}
		mu.Lock()
		if active != nil || epoch == 0xffffffff {
			mu.Unlock()
			c.Close()
			continue
		}
		active = c
		epoch++
		assigned := epoch
		mu.Unlock()
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { c.Close(); mu.Lock(); active = nil; mu.Unlock() }()
			r := bufio.NewReaderSize(c, firewallipc.MaxFrame)
			b, e := readFrame(c, r, true)
			var h hello
			if e != nil || firewallipc.Decode(b, &h) != nil || h != (hello{Version: 1, RuntimeRun: m.RunID, Namespace: m.GatewayNamespace}) {
				return
			}
			_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if json.NewEncoder(c).Encode(hello{Version: 1, RuntimeRun: m.RunID, Run: s.run, Epoch: assigned, Namespace: m.GatewayNamespace}) != nil {
				return
			}
			for {
				b, e = readFrame(c, r, false)
				if e != nil {
					return
				}
				var request firewallipc.Message
				if firewallipc.Decode(b, &request) != nil || request.Sequence>>32 != assigned {
					return
				}
				call, cancel := context.WithTimeout(ctx, 3*time.Second)
				reply, e := s.Handle(call, request)
				cancel()
				if e != nil {
					return
				}
				_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
				if json.NewEncoder(c).Encode(reply) != nil {
					return
				}
			}
		}()
	}
}

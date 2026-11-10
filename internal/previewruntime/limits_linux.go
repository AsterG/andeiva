package previewruntime

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
)

type boundedListener struct {
	net.Listener
	active  atomic.Int32
	allowed netip.Prefix
}
type countedConnection struct {
	net.Conn
	owner *boundedListener
	once  sync.Once
}

func (c *countedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.owner.active.Add(-1) })
	return err
}
func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		remote, e := netip.ParseAddrPort(c.RemoteAddr().String())
		if e != nil || !l.allowed.Contains(remote.Addr().Unmap()) {
			_ = c.Close()
			continue
		}
		if l.active.Add(1) > 64 {
			l.active.Add(-1)
			_ = c.Close()
			continue
		}
		return &countedConnection{Conn: c, owner: l}, nil
	}
}
func admitted(next http.Handler) http.Handler {
	slots := make(chan struct{}, 16)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			next.ServeHTTP(w, r)
		default:
			var id [16]byte
			if _, err := rand.Read(id[:]); err != nil {
				http.Error(w, "ANDEIVA_SERVICE_BUSY", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Request-ID", hex.EncodeToString(id[:]))
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":"ANDEIVA_SERVICE_BUSY","request_id":"` + hex.EncodeToString(id[:]) + `"}`))
		}
	})
}

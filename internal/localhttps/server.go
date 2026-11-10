// Package localhttps serves managed HTTPS bindings without provisioning resources.
package localhttps

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localadmin"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

var ErrUnavailable = errors.New("ANDEIVA_LOCAL_HTTPS_UNAVAILABLE")

const (
	MaxConnections = 32
	MaxRequests    = 16
	DrainTimeout   = 12 * time.Second
)

// Limits must be shared by every managed HTTPS listener in the process.
type Limits struct{ connections, requests chan struct{} }

func NewLimits() *Limits {
	return &Limits{make(chan struct{}, MaxConnections), make(chan struct{}, MaxRequests)}
}

type Options struct {
	Auth           *adminauth.Manager
	Backend        adminapi.LocalBackend
	Inventory      []localpolicy.Interface
	Listener       localpolicy.Listener
	ActivationHash string
	Certificate    tls.Certificate
	Limits         *Limits
	Static         http.Handler
}

type Server struct {
	mu              sync.Mutex
	listener        net.Listener
	connections     map[*connection]struct{}
	http            *http.Server
	address         string
	limits          *Limits
	closed, started bool
	err             error
	wg              sync.WaitGroup
	done            chan struct{}
	drainTimeout    time.Duration
}

// New freezes the endpoint identity and revision. The listener manager remains
// responsible for namespace/interface provenance and applied source policy.
func New(o Options) (*Server, error) {
	l := o.Listener
	a, err := netip.ParseAddr(l.LocalAddress)
	hash, hashErr := hex.DecodeString(o.ActivationHash)
	if o.Auth == nil || o.Backend == nil || o.Limits == nil || cap(o.Limits.connections) != MaxConnections || cap(o.Limits.requests) != MaxRequests ||
		err != nil || a.String() != l.LocalAddress || a.IsUnspecified() || a.IsMulticast() || a.Is4In6() || a.IsLinkLocalUnicast() || a.Zone() != "" ||
		l.Owner != "management" || l.Service != "https" || l.Protocol != localpolicy.TCP || l.Port < 1024 || hashErr != nil || len(hash) != 32 || hex.EncodeToString(hash) != o.ActivationHash {
		return nil, configpoc.ErrInvalid
	}
	inventory, err := localpolicy.Canonical(localpolicy.Config{SchemaVersion: 1, Interfaces: o.Inventory})
	if err != nil {
		return nil, configpoc.ErrInvalid
	}
	found := false
	for _, iface := range inventory.Config.Interfaces {
		for _, address := range iface.Addresses {
			if iface.Name == l.Interface && address == l.LocalAddress {
				found = true
			}
		}
	}
	if !found {
		return nil, configpoc.ErrInvalid
	}
	certificate, err := validatedCertificate(o.Certificate, l.LocalAddress)
	if err != nil {
		return nil, configpoc.ErrInvalid
	}
	address := net.JoinHostPort(l.LocalAddress, strconv.Itoa(int(l.Port)))
	handler, err := adminapi.New(adminapi.Options{Origin: "https://" + address, Auth: o.Auth, Local: o.Backend, LocalEndpointID: localadmin.BindingEndpointID(l), LocalActivationHash: o.ActivationHash, LocalInventory: inventory.Config.Interfaces, Static: o.Static})
	if err != nil {
		return nil, err
	}
	s := &Server{address: address, limits: o.Limits, connections: make(map[*connection]struct{}), done: make(chan struct{}), drainTimeout: DrainTimeout}
	s.http = &http.Server{Handler: s.admit(handler), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}},
		// HTTP/1.1 keeps shared connection/request bounds independent of stream multiplexing.
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	return s, nil
}

func validatedCertificate(input tls.Certificate, address string) (tls.Certificate, error) {
	if len(input.Certificate) == 0 {
		return tls.Certificate{}, configpoc.ErrInvalid
	}
	certificate := tls.Certificate{PrivateKey: input.PrivateKey}
	for _, der := range input.Certificate {
		certificate.Certificate = append(certificate.Certificate, bytes.Clone(der))
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.VerifyHostname(address) != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return tls.Certificate{}, configpoc.ErrInvalid
	}
	signer, ok := input.PrivateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, configpoc.ErrInvalid
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(pub, leaf.RawSubjectPublicKeyInfo) {
		return tls.Certificate{}, configpoc.ErrInvalid
	}
	allowed := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			allowed = true
		}
	}
	if !allowed {
		return tls.Certificate{}, configpoc.ErrInvalid
	}
	certificate.Leaf = leaf
	return certificate, nil
}

func (s *Server) admit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			http.Error(w, ErrUnavailable.Error(), http.StatusServiceUnavailable)
			return
		}
		select {
		case s.limits.requests <- struct{}{}:
			s.wg.Add(1)
		default:
			s.mu.Unlock()
			http.Error(w, ErrUnavailable.Error(), http.StatusServiceUnavailable)
			return
		}
		s.mu.Unlock()
		defer s.wg.Done()
		defer func() { <-s.limits.requests }()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) Serve(listener net.Listener) error {
	if listener == nil || listener.Addr().Network() != "tcp" || listener.Addr().String() != s.address {
		return ErrUnavailable
	}
	s.mu.Lock()
	if s.closed || s.started {
		s.mu.Unlock()
		return ErrUnavailable
	}
	s.started = true
	s.listener = listener
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()
	err := s.http.ServeTLS(&boundedListener{Listener: listener, server: s}, "", "")
	s.mu.Lock()
	stopped := s.closed
	s.mu.Unlock()
	if !stopped {
		s.record(err)
		s.Stop()
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

func (s *Server) record(err error) {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return
	}
	s.mu.Lock()
	// Retain one causal failure, rather than an unbounded chain over connections.
	first := s.err == nil
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	if first {
		// A failed resource close must stop admission. Retire asynchronously:
		// record may be called from a connection's own once-protected Close.
		go s.Stop()
	}
}

// Stop closes active and idle sockets without waiting for the calling operation.
// Backend transactions may finish under their existing bounded detached context.
func (s *Server) Stop() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	listener := s.listener
	connections := make([]*connection, 0, len(s.connections))
	for c := range s.connections {
		connections = append(connections, c)
	}
	s.mu.Unlock()
	if listener != nil {
		s.record(listener.Close())
	}
	for _, c := range connections {
		s.record(c.Close())
	}
	s.record(s.http.Close())
	go func() { s.wg.Wait(); close(s.done) }()
}

// Close joins retired handlers outside activation. A timeout is a failed drain,
// never evidence that a still-running backend operation has completed.
func (s *Server) Close() error {
	s.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), s.drainTimeout)
	defer cancel()
	select {
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.err != nil {
			return errors.Join(ErrUnavailable, s.err)
		}
		return nil
	case <-ctx.Done():
		return errors.Join(ErrUnavailable, ctx.Err())
	}
}

type boundedListener struct {
	net.Listener
	server *Server
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		s := l.server
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			s.record(conn.Close())
			return nil, net.ErrClosed
		}
		select {
		case s.limits.connections <- struct{}{}:
			c := &connection{Conn: conn, server: s}
			s.connections[c] = struct{}{}
			s.mu.Unlock()
			return c, nil
		default:
			s.mu.Unlock()
			s.record(conn.Close())
		}
	}
}

type connection struct {
	net.Conn
	server *Server
	once   sync.Once
	err    error
}

func (c *connection) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.server.mu.Lock()
		delete(c.server.connections, c)
		c.server.mu.Unlock()
		<-c.server.limits.connections
		c.server.record(c.err)
	})
	return c.err
}

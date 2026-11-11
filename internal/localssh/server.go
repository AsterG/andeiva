// Package localssh provides a restricted, authenticated ANDEIVA SSH command
// transport. It never starts an operating-system shell or process.
package localssh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localadmin"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"golang.org/x/crypto/ssh"
)

var ErrUnavailable = errors.New("ANDEIVA_LOCAL_SSH_UNAVAILABLE")

const (
	MaxConnections   = 32
	MaxHandshakes    = 4
	HandshakeTimeout = 5 * time.Second
	CommandTimeout   = 15 * time.Second
)

type Backend interface {
	Execute(context.Context, localadmin.Context, localadmin.Request) (configpoc.Snapshot, error)
	IssueProof(localadmin.Context, localadmin.ProofRequest) (localadmin.Proof, error)
	Status(context.Context, localadmin.Context) (localadmin.Status, error)
	Effective(context.Context, localadmin.Context, localadmin.Filter) (localadmin.Effective, error)
	History(localadmin.Context, uint64, int) ([]configpoc.RevisionEntry, error)
	Audit(localadmin.Context) ([]configpoc.Audit, error)
}

// Limits must be shared by all managed SSH listener instances in the process.
type Limits struct{ connections, handshakes chan struct{} }

func NewLimits() *Limits {
	return &Limits{make(chan struct{}, MaxConnections), make(chan struct{}, MaxHandshakes)}
}

type Options struct {
	Auth           *adminauth.Manager
	Backend        Backend
	Listener       localpolicy.Listener
	ActivationHash string
	HostKey        ssh.Signer
	Limits         *Limits
	Audit          func(adminauth.Event) error
}

type Server struct {
	options                          Options
	mu                               sync.Mutex
	listener                         net.Listener
	connections                      map[net.Conn]context.CancelFunc
	closed                           bool
	failed                           bool
	started                          bool
	wg                               sync.WaitGroup
	handshakeTimeout, commandTimeout time.Duration
}

// New accepts only trusted listener metadata and a provisioned Ed25519 host key.
// The listener owner must verify its namespace/interface/socket provenance.
func New(options Options) (*Server, error) {
	l := options.Listener
	a, err := netip.ParseAddr(l.LocalAddress)
	hash, hashErr := hex.DecodeString(options.ActivationHash)
	if options.Auth == nil || options.Backend == nil || options.HostKey == nil || options.Limits == nil || options.Audit == nil ||
		cap(options.Limits.connections) != MaxConnections || cap(options.Limits.handshakes) != MaxHandshakes ||
		err != nil || a.String() != l.LocalAddress || a.IsUnspecified() || a.IsMulticast() || a.Is4In6() || a.IsLinkLocalUnicast() ||
		l.Owner != "management" || l.Service != "ssh" || l.Interface == "" || l.Protocol != localpolicy.TCP || l.Port < 1024 ||
		hashErr != nil || len(hash) != 32 || hex.EncodeToString(hash) != options.ActivationHash || options.HostKey.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, configpoc.ErrInvalid
	}
	return &Server{options: options, connections: make(map[net.Conn]context.CancelFunc), handshakeTimeout: HandshakeTimeout, commandTimeout: CommandTimeout}, nil
}

func (s *Server) Serve(listener net.Listener) error {
	if listener == nil {
		return ErrUnavailable
	}
	address, err := netip.ParseAddrPort(listener.Addr().String())
	want := s.options.Listener
	if err != nil || address.Addr().String() != want.LocalAddress || address.Port() != want.Port {
		return ErrUnavailable
	}
	s.mu.Lock()
	if s.closed || s.started {
		s.mu.Unlock()
		return ErrUnavailable
	}
	s.listener = listener
	s.started = true
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed, failed := s.closed, s.failed
			s.mu.Unlock()
			if closed && !failed {
				return nil
			}
			s.stop(true)
			return ErrUnavailable
		}
		select {
		case s.options.Limits.connections <- struct{}{}:
		default:
			closeConn(conn)
			continue
		}
		select {
		case s.options.Limits.handshakes <- struct{}{}:
		default:
			<-s.options.Limits.connections
			closeConn(conn)
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			cancel()
			closeConn(conn)
			<-s.options.Limits.connections
			<-s.options.Limits.handshakes
			return nil
		}
		s.connections[conn] = cancel
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serveConnection(ctx, conn)
	}
}

// Stop retires the listener and cancels/closes connections without waiting for
// handlers. Activation callbacks must use Stop: they may themselves be running
// inside an SSH handler. Join with Close only after that callback has returned.
func (s *Server) Stop() { s.stop(false) }

// Close retires and joins listener/connection workers. Never call it from a
// backend/activation callback. Backend methods must honor their context.
func (s *Server) Close() error {
	s.stop(false)
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return ErrUnavailable
	}
	return nil
}
func (s *Server) stop(failed bool) {
	s.mu.Lock()
	s.closed = true
	s.failed = s.failed || failed
	l := s.listener
	connections := make(map[net.Conn]context.CancelFunc, len(s.connections))
	for c, cancel := range s.connections {
		connections[c] = cancel
	}
	s.mu.Unlock()
	if l != nil {
		if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.mu.Lock()
			s.failed = true
			s.mu.Unlock()
		}
	}
	for c, cancel := range connections {
		cancel()
		closeConn(c)
	}
}
func closeConn(c net.Conn) {
	_ = c.Close() /* Connection disposal: no durable state or acknowledgement depends on close. */
}

func (s *Server) event(actor, action, result string) bool {
	if err := s.options.Audit(adminauth.Event{At: time.Now().UTC(), Actor: actor, Action: action, Result: result}); err != nil {
		s.stop(true)
		return false
	}
	return true
}

func (s *Server) serveConnection(parent context.Context, raw net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		cancel := s.connections[raw]
		delete(s.connections, raw)
		s.mu.Unlock()
		cancel()
		closeConn(raw)
		<-s.options.Limits.connections
	}()
	var token string
	borrowed := false
	// Credential login creates an owned provisional session, revoked even after
	// a failed handshake. A borrowed recovery session remains owned by HTTPS.
	defer func() {
		if token != "" && !borrowed {
			if err := s.options.Auth.Logout(token); err != nil && !errors.Is(err, adminauth.ErrDenied) {
				s.stop(true)
			}
		}
	}()
	algs := ssh.SupportedAlgorithms()
	config := &ssh.ServerConfig{Config: ssh.Config{KeyExchanges: algs.KeyExchanges, Ciphers: algs.Ciphers, MACs: algs.MACs}, MaxAuthTries: 3, ServerVersion: "SSH-2.0-ANDEIVA"}
	config.PasswordCallback = func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		defer clear(password)
		if token != "" {
			return nil, adminauth.ErrDenied
		}
		if len(password) == len("session:")+64 && strings.HasPrefix(string(password), "session:") {
			candidate := string(password[len("session:"):])
			id, err := s.options.Auth.Authenticate(candidate)
			if err != nil || id.Username != meta.User() {
				_ = s.options.Auth.RecordDenied("unknown", "write")
				return nil, adminauth.ErrDenied
			}
			token = candidate
			borrowed = true
			return &ssh.Permissions{}, nil
		}
		credential := ""
		if len(password) == 64 {
			credential = string(password)
		}
		remote := meta.RemoteAddr()
		if remote == nil {
			return nil, adminauth.ErrDenied
		}
		peer, err := netip.ParseAddrPort(remote.String())
		if err != nil {
			return nil, adminauth.ErrDenied
		}
		_, newToken, err := s.options.Auth.LoginFrom(peer.Addr(), meta.User(), credential)
		if err != nil {
			return nil, err
		}
		token = newToken
		return &ssh.Permissions{}, nil
	}
	config.AddHostKey(s.options.HostKey)
	if err := raw.SetDeadline(time.Now().Add(s.handshakeTimeout)); err != nil {
		<-s.options.Limits.handshakes
		return
	}
	connection, channels, requests, err := ssh.NewServerConn(raw, config)
	<-s.options.Limits.handshakes
	if err != nil {
		return
	}
	defer func() { _ = connection.Close(); _ = connection.Wait() }()
	id, err := s.options.Auth.Authenticate(token)
	if err != nil || id.Username != connection.User() {
		return
	}
	if !s.event(id.Username, "ssh-auth", "ok") {
		return
	}
	sum := sha256.Sum256([]byte(token))
	caller := localadmin.Context{Principal: configpoc.Principal{ID: id.Username, Role: configpoc.Role(id.Role)}, Surface: configpoc.CLI, SessionHash: hex.EncodeToString(sum[:]), EndpointID: localadmin.BindingEndpointID(s.options.Listener), ActivationHash: s.options.ActivationHash}
	ctx, cancel := context.WithTimeout(parent, s.commandTimeout)
	defer cancel()
	if err := raw.SetDeadline(time.Now().Add(s.commandTimeout)); err != nil {
		return
	}
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		for request := range requests {
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
			s.event(id.Username, "ssh-channel", "denied")
			closeConn(raw)
			return
		}
	}()
	defer func() { closeConn(raw); <-requestDone }()
	select {
	case <-ctx.Done():
		return
	case incoming, ok := <-channels:
		if !ok {
			return
		}
		if incoming.ChannelType() != "session" || len(incoming.ExtraData()) != 0 {
			_ = incoming.Reject(ssh.Prohibited, "ANDEIVA_SSH_CHANNEL_DENIED")
			s.event(id.Username, "ssh-channel", "denied")
			return
		}
		channel, channelRequests, err := incoming.Accept()
		if err != nil {
			return
		}
		defer func() { _ = channel.Close() }()
		additionalDone := make(chan struct{})
		go func() {
			defer close(additionalDone)
			for extra := range channels {
				_ = extra.Reject(ssh.Prohibited, "ANDEIVA_SSH_CHANNEL_DENIED")
				s.event(id.Username, "ssh-channel", "denied")
				closeConn(raw)
				return
			}
		}()
		defer func() { closeConn(raw); <-additionalDone }()
		s.command(ctx, channel, channelRequests, caller, token)
	}
}

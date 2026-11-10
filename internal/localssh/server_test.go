package localssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localadmin"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"golang.org/x/crypto/ssh"
)

type testBackend struct {
	mu        sync.Mutex
	callers   []localadmin.Context
	requests  []localadmin.Request
	block     atomic.Bool
	entered   chan struct{}
	onExecute func()
}

func (b *testBackend) record(c localadmin.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.callers = append(b.callers, c)
}
func (b *testBackend) Execute(_ context.Context, c localadmin.Context, r localadmin.Request) (configpoc.Snapshot, error) {
	b.record(c)
	b.mu.Lock()
	b.requests = append(b.requests, r)
	b.mu.Unlock()
	if b.onExecute != nil {
		b.onExecute()
	}
	return configpoc.Snapshot{Generation: 7}, nil
}
func (b *testBackend) IssueProof(c localadmin.Context, r localadmin.ProofRequest) (localadmin.Proof, error) {
	b.record(c)
	return localadmin.Proof{Token: "unit-adapter-proof", ExpiresAt: time.Now().Add(time.Second)}, nil
}
func (b *testBackend) Status(ctx context.Context, c localadmin.Context) (localadmin.Status, error) {
	b.record(c)
	if b.block.Load() {
		close(b.entered)
		<-ctx.Done()
		return localadmin.Status{}, ctx.Err()
	}
	return localadmin.Status{Snapshot: configpoc.Snapshot{Generation: 7}}, nil
}
func (b *testBackend) Effective(_ context.Context, c localadmin.Context, _ localadmin.Filter) (localadmin.Effective, error) {
	b.record(c)
	return localadmin.Effective{Phase: "idle"}, nil
}
func (b *testBackend) History(c localadmin.Context, _ uint64, _ int) ([]configpoc.RevisionEntry, error) {
	b.record(c)
	return []configpoc.RevisionEntry{}, nil
}
func (b *testBackend) Audit(c localadmin.Context) ([]configpoc.Audit, error) {
	b.record(c)
	return []configpoc.Audit{}, nil
}
func (b *testBackend) count() int { b.mu.Lock(); defer b.mu.Unlock(); return len(b.callers) }

type testAudit struct {
	mu          sync.Mutex
	events      []adminauth.Event
	login       atomic.Bool
	failCommand bool
}

func (a *testAudit) append(e adminauth.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failCommand && e.Action == "ssh-command" {
		return errors.New("private diagnostic")
	}
	a.events = append(a.events, e)
	if e.Action == "login" && e.Result == "ok" {
		a.login.Store(true)
	}
	return nil
}
func (a *testAudit) counts() (int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	login, logout := 0, 0
	for _, e := range a.events {
		if e.Action == "login" && e.Result == "ok" {
			login++
		}
		if e.Action == "logout" && e.Result == "ok" {
			logout++
		}
	}
	return login, logout
}

type harness struct {
	server     *Server
	backend    *testBackend
	audit      *testAudit
	auth       *adminauth.Manager
	signer     ssh.Signer
	credential string
	address    string
	served     chan error
}

func newHarness(t *testing.T, role string, configure func(*Server), wrap func(net.Listener, *testAudit) net.Listener) *harness {
	t.Helper()
	var credential [32]byte
	if _, err := rand.Read(credential[:]); err != nil {
		t.Fatal(err)
	}
	secret := hex.EncodeToString(credential[:])
	sum := sha256.Sum256([]byte(secret))
	audit := &testAudit{}
	auth, err := adminauth.New([]adminauth.Account{{Username: "operator", Role: role, CredentialSHA256: hex.EncodeToString(sum[:])}}, audit.append)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	addr, err := netip.ParseAddrPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	backend := &testBackend{entered: make(chan struct{})}
	server, err := New(Options{Auth: auth, Backend: backend, Listener: localpolicy.Listener{Owner: "management", Service: "ssh", Interface: "isolated-test", LocalAddress: addr.Addr().String(), Protocol: localpolicy.TCP, Port: addr.Port()}, ActivationHash: strings.Repeat("a", 64), HostKey: signer, Limits: NewLimits(), Audit: audit.append})
	if err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(server)
	}
	if wrap != nil {
		l = wrap(l, audit)
	}
	h := &harness{server: server, backend: backend, audit: audit, auth: auth, signer: signer, credential: secret, address: l.Addr().String(), served: make(chan error, 1)}
	go func() { h.served <- server.Serve(l) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-h.served:
		case <-time.After(time.Second):
			t.Error("Serve not stopped")
		}
	})
	return h
}
func (h *harness) config() *ssh.ClientConfig {
	a := ssh.SupportedAlgorithms()
	return &ssh.ClientConfig{User: "operator", Auth: []ssh.AuthMethod{ssh.Password(h.credential)}, HostKeyCallback: ssh.FixedHostKey(h.signer.PublicKey()), HostKeyAlgorithms: a.HostKeys, Timeout: time.Second, Config: ssh.Config{KeyExchanges: a.KeyExchanges, Ciphers: a.Ciphers, MACs: a.MACs}}
}
func (h *harness) client(t *testing.T) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", h.address, h.config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func (h *harness) run(t *testing.T, command, input string) ([]byte, error) {
	t.Helper()
	client := h.client(t)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	session.Stdin = strings.NewReader(input)
	return session.Output(command)
}
func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRealSSHAuthenticatedStatusAndProofContext(t *testing.T) {
	h := newHarness(t, "admin", nil, nil)
	output, err := h.run(t, "andeiva local-services status", "")
	if err != nil || !bytes.Contains(output, []byte(`"generation":7`)) {
		t.Fatalf("status: %s %v", output, err)
	}
	output, err = h.run(t, "andeiva local-services proof", `{"generation":7,"target":"`+strings.Repeat("b", 64)+`","lease":"pending"}`)
	if err != nil || !bytes.Contains(output, []byte("unit-adapter-proof")) {
		t.Fatalf("proof adapter: %s %v", output, err)
	}
	h.backend.mu.Lock()
	callers := append([]localadmin.Context(nil), h.backend.callers...)
	h.backend.mu.Unlock()
	for _, c := range callers {
		if c.Principal.ID != "operator" || c.Principal.Role != configpoc.RoleAdmin || c.Surface != configpoc.CLI || c.EndpointID != localadmin.BindingEndpointID(h.server.options.Listener) || c.ActivationHash != h.server.options.ActivationHash || len(c.SessionHash) != 64 {
			t.Fatalf("untrusted context: %+v", c)
		}
	}
	if callers[0].SessionHash == callers[1].SessionHash {
		t.Fatal("distinct SSH sessions shared auth token")
	}
	waitFor(t, func() bool { a, b := h.audit.counts(); return a == 2 && b == 2 })
	h.audit.mu.Lock()
	serialized, _ := json.Marshal(h.audit.events)
	h.audit.mu.Unlock()
	if bytes.Contains(serialized, []byte(h.credential)) || bytes.Contains(serialized, []byte("pending")) {
		t.Fatal("secret or request content leaked into audit")
	}
}

func TestViewerCannotWriteOrReadProtectedHistory(t *testing.T) {
	for _, verb := range []string{"execute", "proof", "history", "audit"} {
		t.Run(verb, func(t *testing.T) {
			h := newHarness(t, "viewer", nil, nil)
			output, err := h.run(t, "andeiva local-services "+verb, "{}")
			if err == nil || !bytes.Contains(output, []byte(configpoc.ErrDenied.Error())) || h.backend.count() != 0 {
				t.Fatalf("viewer reached backend: %s %v", output, err)
			}
		})
	}
	h := newHarness(t, "viewer", nil, nil)
	if _, err := h.run(t, "andeiva local-services effective", "{}"); err != nil || h.backend.count() != 1 {
		t.Fatal(err)
	}
}

func TestClosedCommandGrammarAndSessionRequests(t *testing.T) {
	for _, command := range []string{"sh", "scp -t /tmp/file", "andeiva local-services status; id", "andeiva local-services status\n", "andeiva local-services status extra", "andeiva local-services execute $(id)"} {
		t.Run(command, func(t *testing.T) {
			h := newHarness(t, "admin", nil, nil)
			if _, err := h.run(t, command, ""); err == nil || h.backend.count() != 0 {
				t.Fatal("arbitrary command accepted")
			}
		})
	}
	for _, kind := range []string{"shell", "pty-req", "env", "subsystem", "auth-agent-req@openssh.com"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t, "admin", nil, nil)
			client := h.client(t)
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = session.Close() }()
			ok, err := session.SendRequest(kind, true, nil)
			if ok || h.backend.count() != 0 {
				t.Fatalf("request accepted: %v", err)
			}
		})
	}
}

func TestChannelAndGlobalForwardingDenied(t *testing.T) {
	for _, kind := range []string{"direct-tcpip", "forwarded-tcpip", "direct-streamlocal@openssh.com"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t, "admin", nil, nil)
			client := h.client(t)
			ch, _, err := client.OpenChannel(kind, nil)
			if err == nil {
				_ = ch.Close()
				t.Fatal("forwarding accepted")
			}
			if h.backend.count() != 0 {
				t.Fatal("forward touched backend")
			}
		})
	}
	h := newHarness(t, "admin", nil, nil)
	client := h.client(t)
	ok, _, err := client.SendRequest("tcpip-forward", true, nil)
	if ok {
		t.Fatalf("global forward accepted: %v", err)
	}
}

func TestAdditionalSessionAndUnverifiedHostKeyRejected(t *testing.T) {
	h := newHarness(t, "admin", nil, nil)
	client := h.client(t)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	second, err := client.NewSession()
	if err == nil {
		_ = second.Close()
		t.Fatal("second session accepted")
	}
	if h.backend.count() != 0 {
		t.Fatal("extra channel invoked backend")
	}
	h2 := newHarness(t, "admin", nil, nil)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := h2.config()
	config.HostKeyCallback = ssh.FixedHostKey(wrong.PublicKey())
	bad, err := ssh.Dial("tcp", h2.address, config)
	if err == nil {
		_ = bad.Close()
		t.Fatal("unverified host accepted")
	}
	if h2.audit.login.Load() {
		t.Fatal("credential sent before host key verification")
	}
}

func TestStrictBoundedInputAndTransactions(t *testing.T) {
	for _, input := range []string{`{"principal":"other"}`, `{} {}`, `null`, `{"transaction":{"operation":"stage","Operation":"commit"}}`, `{"transaction":{"target":"a","target":"b"}}`, strings.Repeat(" ", MaxInputBytes+1)} {
		t.Run(input[:min(len(input), 20)], func(t *testing.T) {
			h := newHarness(t, "admin", nil, nil)
			output, err := h.run(t, "andeiva local-services execute", input)
			if err == nil || !bytes.Contains(output, []byte(configpoc.ErrInvalid.Error())) || h.backend.count() != 0 {
				t.Fatalf("invalid input passed: %s %v", output, err)
			}
		})
	}
	h := newHarness(t, "admin", nil, nil)
	r := localadmin.Request{Transaction: configpoc.Request{Operation: configpoc.OpStage, Key: "stage", ExpectedGeneration: 7}, RecoveryProof: "opaque"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.run(t, "andeiva local-services execute", string(b)); err != nil {
		t.Fatal(err)
	}
	h.backend.mu.Lock()
	defer h.backend.mu.Unlock()
	if len(h.backend.requests) != 1 || h.backend.requests[0].Transaction.Key != "stage" || h.backend.requests[0].RecoveryProof != "opaque" {
		t.Fatal("typed request changed")
	}
}

func TestExecuteCanRetireItsOwnListener(t *testing.T) {
	h := newHarness(t, "admin", nil, nil)
	returned := make(chan struct{})
	h.backend.onExecute = func() { h.server.Stop(); close(returned) }
	client := h.client(t)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	session.Stdin = strings.NewReader(`{"transaction":{"operation":"commit","key":"retire","expected_generation":7}}`)
	done := make(chan error, 1)
	go func() { done <- session.Run("andeiva local-services execute") }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("retire waited on its own backend callback")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retired SSH connection remained active")
	}
	if err := h.server.Close(); err != nil {
		t.Fatal(err)
	}
	if h.backend.count() != 1 || len(h.server.options.Limits.connections) != 0 {
		t.Fatal("retirement did not drain")
	}
}

func BenchmarkDecodeProof(b *testing.B) {
	input := `{"generation":7,"target":"` + strings.Repeat("a", 64) + `","lease":"pending"}`
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var request localadmin.ProofRequest
		if err := decode(strings.NewReader(input), &request); err != nil {
			b.Fatal(err)
		}
	}
}

func TestFailedAuthenticationAndMaxTries(t *testing.T) {
	h := newHarness(t, "admin", nil, nil)
	config := h.config()
	config.Auth = []ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.Password(strings.Repeat("0", 64)), 5)}
	client, err := ssh.Dial("tcp", h.address, config)
	if err == nil {
		_ = client.Close()
		t.Fatal("bad credentials accepted")
	}
	if h.backend.count() != 0 {
		t.Fatal("failed auth reached backend")
	}
	h.audit.mu.Lock()
	denials := 0
	for _, e := range h.audit.events {
		if e.Action == "login" && e.Result == "denied" {
			denials++
		}
	}
	h.audit.mu.Unlock()
	if denials != 3 {
		t.Fatalf("MaxAuthTries got %d", denials)
	}
}

type failAuthListener struct {
	net.Listener
	audit *testAudit
}
type failAuthConn struct {
	net.Conn
	audit *testAudit
}

func (l failAuthListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return failAuthConn{c, l.audit}, nil
}
func (c failAuthConn) Write(b []byte) (int, error) {
	if c.audit.login.Load() {
		_ = c.Conn.Close()
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(b)
}
func TestFailedHandshakeRevokesProvisionalSession(t *testing.T) {
	h := newHarness(t, "admin", nil, func(l net.Listener, a *testAudit) net.Listener { return failAuthListener{l, a} })
	client, err := ssh.Dial("tcp", h.address, h.config())
	if err == nil {
		_ = client.Close()
		t.Fatal("broken auth handshake succeeded")
	}
	waitFor(t, func() bool { a, b := h.audit.counts(); return a == 1 && b == 1 })
	if h.backend.count() != 0 {
		t.Fatal("incomplete authentication produced principal")
	}
}

func TestBorrowedRecoverySessionRetainedAndBound(t *testing.T) {
	h := newHarness(t, "admin", nil, nil)
	_, token, err := h.auth.Login("operator", h.credential)
	if err != nil {
		t.Fatal(err)
	}
	h.credential = "session:" + token
	if _, err = h.run(t, "andeiva local-services status", ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(h.server.options.Limits.connections) == 0 })
	if _, err = h.auth.Authenticate(token); err != nil {
		t.Fatal("SSH closed borrowed recovery session")
	}
	h.backend.mu.Lock()
	caller := h.backend.callers[0]
	h.backend.mu.Unlock()
	sum := sha256.Sum256([]byte(token))
	if caller.SessionHash != hex.EncodeToString(sum[:]) {
		t.Fatal("SSH did not bind recovery session")
	}
	_, logout := h.audit.counts()
	if logout != 0 {
		t.Fatal("borrowed session logged out")
	}
}

func TestBorrowedSessionFailures(t *testing.T) {
	for _, kind := range []string{"revoked", "wrong-user", "credential-as-session", "raw-token"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t, "admin", nil, nil)
			credential := h.credential
			_, token, err := h.auth.Login("operator", credential)
			if err != nil {
				t.Fatal(err)
			}
			config := h.config()
			value := "session:" + token
			switch kind {
			case "revoked":
				if err = h.auth.Revoke("operator"); err != nil {
					t.Fatal(err)
				}
			case "wrong-user":
				config.User = "other"
			case "credential-as-session":
				value = "session:" + credential
			case "raw-token":
				value = token
			}
			config.Auth = []ssh.AuthMethod{ssh.Password(value)}
			client, err := ssh.Dial("tcp", h.address, config)
			if err == nil {
				_ = client.Close()
				t.Fatal("invalid session binding authenticated")
			}
			if h.backend.count() != 0 {
				t.Fatal("invalid session reached backend")
			}
		})
	}
}

func TestRevocationAfterInputWait(t *testing.T) {
	h := newHarness(t, "admin", nil, nil)
	client := h.client(t)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	input, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	session.Stdout = &output
	if err = session.Start("andeiva local-services proof"); err != nil {
		t.Fatal(err)
	}
	if err = h.auth.Revoke("operator"); err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(input, `{"generation":7,"target":"`+strings.Repeat("a", 64)+`","lease":"proof"}`); err != nil {
		t.Fatal(err)
	}
	if err = input.Close(); err != nil {
		t.Fatal(err)
	}
	if err = session.Wait(); err == nil || h.backend.count() != 0 {
		t.Fatalf("revoked session invoked backend: %s %v", output.Bytes(), err)
	}
}

func TestTimeoutsAndCloseDrain(t *testing.T) {
	h := newHarness(t, "admin", func(s *Server) { s.handshakeTimeout = 60 * time.Millisecond; s.commandTimeout = 80 * time.Millisecond }, nil)
	raw, err := net.Dial("tcp", h.address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if err = raw.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, _ = io.ReadAll(raw)
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("stalled handshake not closed")
	}
	client := h.client(t)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	input, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close() }()
	if err = session.Start("andeiva local-services proof"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stdin timeout not enforced")
	}
	h2 := newHarness(t, "admin", nil, nil)
	h2.backend.block.Store(true)
	client2 := h2.client(t)
	session2, err := client2.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session2.Close() }()
	if err = session2.Start("andeiva local-services status"); err != nil {
		t.Fatal(err)
	}
	<-h2.backend.entered
	closed := make(chan error, 1)
	go func() { closed <- h2.server.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel/drain handler")
	}
	if len(h2.server.options.Limits.connections) != 0 || len(h2.server.options.Limits.handshakes) != 0 {
		t.Fatal("capacity leaked on close")
	}
}

func TestSharedLimitsAndAuditFailure(t *testing.T) {
	h := newHarness(t, "admin", nil, nil)
	for range MaxHandshakes {
		h.server.options.Limits.handshakes <- struct{}{}
	}
	c, err := net.Dial("tcp", h.address)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err = c.Read(b); err == nil {
		t.Fatal("handshake limit ignored")
	}
	_ = c.Close()
	for range MaxHandshakes {
		<-h.server.options.Limits.handshakes
	}
	for range MaxConnections {
		h.server.options.Limits.connections <- struct{}{}
	}
	c, err = net.Dial("tcp", h.address)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Read(b); err == nil {
		t.Fatal("connection limit ignored")
	}
	_ = c.Close()
	for range MaxConnections {
		<-h.server.options.Limits.connections
	}
	h.audit.mu.Lock()
	h.audit.failCommand = true
	h.audit.mu.Unlock()
	if _, err = h.run(t, "andeiva local-services status", ""); err == nil {
		t.Fatal("audit failure reported success")
	}
	if !errors.Is(h.server.Close(), ErrUnavailable) {
		t.Fatal("audit failure did not latch closed")
	}
}

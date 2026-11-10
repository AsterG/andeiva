package localhttps

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localadmin"
	"github.com/AsterG/andeiva/internal/locallistener"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

var _ locallistener.Server = (*Server)(nil)

type backend struct {
	mu      sync.Mutex
	callers []localadmin.Context
	execute func()
}

func (b *backend) record(c localadmin.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.callers = append(b.callers, c)
}
func (b *backend) Execute(_ context.Context, c localadmin.Context, _ localadmin.Request) (configpoc.Snapshot, error) {
	b.record(c)
	if b.execute != nil {
		b.execute()
	}
	return configpoc.Snapshot{}, nil
}
func (b *backend) Status(_ context.Context, c localadmin.Context) (localadmin.Status, error) {
	b.record(c)
	return localadmin.Status{}, nil
}
func (b *backend) Effective(_ context.Context, c localadmin.Context, _ localadmin.Filter) (localadmin.Effective, error) {
	b.record(c)
	return localadmin.Effective{}, nil
}
func (b *backend) History(c localadmin.Context, _ uint64, _ int) ([]configpoc.RevisionEntry, error) {
	b.record(c)
	return nil, nil
}
func (b *backend) Audit(c localadmin.Context) ([]configpoc.Audit, error) {
	b.record(c)
	return nil, nil
}
func (b *backend) IssueProof(c localadmin.Context, _ localadmin.ProofRequest) (localadmin.Proof, error) {
	b.record(c)
	return localadmin.Proof{}, nil
}

type fixture struct {
	s       *Server
	b       *backend
	options Options
	client  *http.Client
	address string
	secret  string
	served  chan error
}

type readyListener struct {
	net.Listener
	ready chan struct{}
	once  sync.Once
}

func (l *readyListener) Accept() (net.Conn, error) {
	l.once.Do(func() { close(l.ready) })
	return l.Listener.Accept()
}

func certificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local transport test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafPub, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: leafKey}, roots
}

func newFixture(t *testing.T, role string, limits *Limits, configure func(*Server), wrap func(net.Listener) net.Listener) *fixture {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	ap := netip.MustParseAddrPort(l.Addr().String())
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	f := &fixture{b: &backend{}, secret: hex.EncodeToString(secret), address: "https://" + l.Addr().String(), served: make(chan error, 1)}
	digest := sha256.Sum256([]byte(f.secret))
	auth, err := adminauth.New([]adminauth.Account{{Username: "alice", Role: role, CredentialSHA256: hex.EncodeToString(digest[:])}}, func(adminauth.Event) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	pair, roots := certificate(t)
	f.options = Options{Auth: auth, Backend: f.b, Inventory: []localpolicy.Interface{{Name: "lo", Zone: localpolicy.LAN, Addresses: []string{"127.0.0.1"}}}, Listener: localpolicy.Listener{Owner: "management", Service: "https", Interface: "lo", LocalAddress: "127.0.0.1", Protocol: localpolicy.TCP, Port: ap.Port()}, ActivationHash: strings.Repeat("a", 64), Certificate: pair, Limits: limits}
	f.s, err = New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(f.s)
	}
	f.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}, Timeout: 3 * time.Second}
	t.Cleanup(f.client.CloseIdleConnections)
	listener := l
	if wrap != nil {
		listener = wrap(l)
	}
	ready := &readyListener{Listener: listener, ready: make(chan struct{})}
	go func() { f.served <- f.s.Serve(ready) }()
	t.Cleanup(func() {
		if err := f.s.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-f.served:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("serve did not stop")
		}
	})
	// Metadata-only tests may finish without a request. Establish that Serve
	// owns the listener before cleanup can stop it; a goroutine launch is not
	// evidence that the server has started.
	select {
	case <-ready.ready:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not reach accept")
	}
	return f
}

func (f *fixture) request(t *testing.T, method, path string, body any, headers map[string]string) (int, []byte, http.Header) {
	t.Helper()
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err := http.NewRequest(method, f.address+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		if k == "Host" {
			r.Host = v
		} else {
			r.Header.Set(k, v)
		}
	}
	response, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("unverified TLS")
	}
	defer response.Body.Close()
	out, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, out, response.Header
}
func (f *fixture) login(t *testing.T, web bool) (string, http.Header) {
	t.Helper()
	client := "api"
	if web {
		client = "web"
	}
	status, data, h := f.request(t, "POST", "/api/v1/auth/login", map[string]string{"username": "alice", "credential": f.secret}, map[string]string{"Content-Type": "application/json", "Origin": f.address, "X-ANDEIVA-Client": client})
	if status != 200 {
		t.Fatalf("login status %d", status)
	}
	var value struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value.Token, h
}

func TestTLSAuthContextAndSessionRevocation(t *testing.T) {
	f := newFixture(t, "admin", NewLimits(), nil, nil)
	if status, _, _ := f.request(t, "GET", "/api/v1/local-services", nil, nil); status != 401 {
		t.Fatal(status)
	}
	token, _ := f.login(t, false)
	headers := map[string]string{"Authorization": "Bearer " + token, "X-ANDEIVA-Client": "cli", "X-Endpoint-ID": "forged", "X-Activation-Hash": strings.Repeat("f", 64)}
	if status, _, _ := f.request(t, "GET", "/api/v1/local-services", nil, headers); status != 200 {
		t.Fatal(status)
	}
	f.b.mu.Lock()
	caller := f.b.callers[0]
	f.b.mu.Unlock()
	hash := sha256.Sum256([]byte(token))
	if caller.EndpointID != localadmin.BindingEndpointID(f.options.Listener) || caller.ActivationHash != f.options.ActivationHash || caller.SessionHash != hex.EncodeToString(hash[:]) || caller.Principal.ID != "alice" || caller.Surface != configpoc.CLI {
		t.Fatal("trusted context mismatch")
	}
	headers["Origin"] = "https://example.invalid"
	if status, _, _ := f.request(t, "GET", "/api/v1/local-services", nil, headers); status != 403 {
		t.Fatal(status)
	}
	delete(headers, "Origin")
	headers["Host"] = "example.invalid"
	if status, _, _ := f.request(t, "GET", "/api/v1/local-services", nil, headers); status != 403 {
		t.Fatal(status)
	}
	delete(headers, "Host")
	if err := f.options.Auth.Logout(token); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := f.request(t, "GET", "/api/v1/local-services", nil, headers); status != 401 {
		t.Fatal(status)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool()}}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Get(f.address)
	if err == nil {
		resp.Body.Close()
		t.Fatal("untrusted CA accepted")
	}
}

func TestRBACAndCookieCSRF(t *testing.T) {
	for _, role := range []string{"admin", "viewer"} {
		t.Run(role, func(t *testing.T) {
			f := newFixture(t, role, NewLimits(), nil, nil)
			token, _ := f.login(t, false)
			h := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}
			if role == "viewer" {
				for _, path := range []string{"/api/v1/local-services/transactions", "/api/v1/local-services/proofs"} {
					if status, _, _ := f.request(t, "POST", path, localadmin.Request{Transaction: configpoc.Request{Operation: configpoc.OpValidate}}, h); status != 403 {
						t.Fatal(status)
					}
				}
				if status, _, _ := f.request(t, "GET", "/api/v1/local-services/history", nil, h); status != 403 {
					t.Fatal(status)
				}
			}
			_, cookie := f.login(t, true)
			cookies := (&http.Response{Header: cookie}).Cookies()
			if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
				t.Fatal("cookie")
			}
			h = map[string]string{"Cookie": cookies[0].Name + "=" + cookies[0].Value, "Content-Type": "application/json", "Origin": f.address}
			if status, _, _ := f.request(t, "POST", "/api/v1/local-services/transactions", localadmin.Request{Transaction: configpoc.Request{Operation: configpoc.OpValidate}}, h); status != 403 {
				t.Fatal(status)
			}
			f.b.mu.Lock()
			defer f.b.mu.Unlock()
			if len(f.b.callers) != 0 {
				t.Fatal("denied request reached backend")
			}
		})
	}
}

func TestStopInsideTransactionAndDrain(t *testing.T) {
	f := newFixture(t, "admin", NewLimits(), nil, nil)
	token, _ := f.login(t, false)
	stopped := make(chan struct{})
	release := make(chan struct{})
	f.b.execute = func() { f.s.Stop(); close(stopped); <-release }
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		body, _ := json.Marshal(localadmin.Request{Transaction: configpoc.Request{Operation: configpoc.OpValidate}})
		r, _ := http.NewRequest("POST", f.address+"/api/v1/local-services/transactions", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		res, err := f.client.Do(r)
		if err == nil {
			res.Body.Close()
		}
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("self stop blocked")
	}
	closed := make(chan error, 1)
	go func() { closed <- f.s.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("premature drain %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	<-requestDone
	if _, err := f.options.Auth.Authenticate(token); err != nil {
		t.Fatal("shared session was revoked")
	}
}

func TestDrainTimeoutAndSharedRequestLimit(t *testing.T) {
	limits := NewLimits()
	entered := make(chan struct{}, MaxRequests)
	release := make(chan struct{})
	static := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { entered <- struct{}{}; <-release })
	f := newFixture(t, "admin", limits, func(s *Server) { s.http.Handler = s.admit(static); s.drainTimeout = 40 * time.Millisecond }, nil)
	g := newFixture(t, "admin", limits, nil, nil)
	var wg sync.WaitGroup
	for range MaxRequests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := f.client.Get(f.address)
			if err == nil {
				r.Body.Close()
			}
		}()
	}
	for range MaxRequests {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("handler did not enter")
		}
	}
	if status, _, _ := g.request(t, "GET", "/api/v1/local-services", nil, nil); status != 503 {
		t.Fatal(status)
	}
	if err := f.s.Close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want bounded drain timeout: %v", err)
	}
	close(release)
	wg.Wait()
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(limits.requests) != 0 {
		t.Fatal("request slots leaked")
	}
}

func TestMetadataAndCertificateValidation(t *testing.T) {
	f := newFixture(t, "admin", NewLimits(), nil, nil)
	for _, mutate := range []func(*Options){func(o *Options) { o.Listener.Port = 443 }, func(o *Options) { o.Listener.LocalAddress = "0.0.0.0" }, func(o *Options) { o.Listener.Interface = "other" }, func(o *Options) { o.ActivationHash = "bad" }, func(o *Options) { o.Certificate = tls.Certificate{} }, func(o *Options) { o.Listener.Service = "ssh" }, func(o *Options) { o.Limits = nil }, func(o *Options) {
		o.Listener.LocalAddress = "127.0.0.2"
		o.Inventory = []localpolicy.Interface{{Name: "lo", Zone: localpolicy.LAN, Addresses: []string{"127.0.0.2"}}}
	}} {
		o := f.options
		mutate(&o)
		if _, err := New(o); err == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
	o := f.options
	other, _ := certificate(t)
	o.Certificate.PrivateKey = other.PrivateKey
	if _, err := New(o); err == nil {
		t.Fatal("mismatched key accepted")
	}
	s, err := New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := s.Serve(l); !errors.Is(err, ErrUnavailable) {
		t.Fatal("wrong listener accepted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

type failedClose struct {
	net.Listener
	failure error
}

func (l *failedClose) Close() error { return errors.Join(l.Listener.Close(), l.failure) }
func TestClosePropagatesListenerFailure(t *testing.T) {
	failure := errors.New("test close failure")
	f := newFixture(t, "admin", NewLimits(), nil, func(l net.Listener) net.Listener { return &failedClose{l, failure} })
	f.login(t, false)
	if err := f.s.Close(); !errors.Is(err, failure) {
		t.Fatalf("lost close error: %v", err)
	}
	// The expected failure is sticky; fixture cleanup checks the subsequent drain.
	f.s.mu.Lock()
	f.s.err = nil
	f.s.mu.Unlock()
}

func TestSharedConnectionsAndHandshakeRetirement(t *testing.T) {
	limits := NewLimits()
	f := newFixture(t, "admin", limits, nil, nil)
	g := newFixture(t, "admin", limits, nil, nil)
	var connections []net.Conn
	defer func() {
		for _, c := range connections {
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	for range MaxConnections {
		c, err := net.DialTimeout("tcp", strings.TrimPrefix(f.address, "https://"), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, c)
	}
	deadline := time.Now().Add(time.Second)
	for len(limits.connections) != MaxConnections && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(limits.connections) != MaxConnections {
		t.Fatal("connection limit not reached")
	}
	c, err := net.DialTimeout("tcp", strings.TrimPrefix(g.address, "https://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connections = append(connections, c)
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := c.Read(data[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("excess connection not retired: %v", err)
	}
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(limits.connections) != 0 {
		t.Fatal("connection slots leaked")
	}
	if status, _, _ := g.request(t, "GET", "/api/v1/local-services", nil, nil); status != 401 {
		t.Fatal(status)
	}
}

func TestHandshakeDeadlineAndTLSFloor(t *testing.T) {
	f := newFixture(t, "admin", NewLimits(), func(s *Server) { s.http.ReadHeaderTimeout = 40 * time.Millisecond }, nil)
	c, err := net.DialTimeout("tcp", strings.TrimPrefix(f.address, "https://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := c.Read(data[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("slow handshake not closed: %v", err)
	}
	config := f.client.Transport.(*http.Transport).TLSClientConfig.Clone()
	config.MinVersion = tls.VersionTLS12
	config.MaxVersion = tls.VersionTLS12
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: config}, Timeout: time.Second}
	defer old.CloseIdleConnections()
	res, err := old.Get(f.address)
	if err == nil {
		res.Body.Close()
		t.Fatal("TLS 1.2 accepted")
	}
}

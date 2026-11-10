//go:build linux

package localruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/adminclient"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localadmin"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/localssh"
	"github.com/AsterG/andeiva/internal/nftfixture"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func testConfig() Config {
	return Config{LANAddress: "192.0.2.1", LANInterface: "eth0", AllowedCIDR: "192.0.2.10/32", APIUser: "lab-api", APIGroup: "lab-api", HelperUser: "lab-helper", HelperGroup: "lab-helper", WebRoot: "/opt/lab/web"}
}
func TestConfigurationBoundaries(t *testing.T) {
	c := testConfig()
	if c.Validate() != nil {
		t.Fatal("source prefix must be independent from listener")
	}
	for _, change := range []func(*Config){func(c *Config) { c.LANAddress = "0.0.0.0" }, func(c *Config) { c.LANAddress = "127.0.0.1" }, func(c *Config) { c.AllowedCIDR = "0.0.0.0/0" }, func(c *Config) { c.LANInterface = "eth0\nother" }, func(c *Config) { c.HelperUser = c.APIUser }, func(c *Config) { c.HelperGroup = c.APIGroup }, func(c *Config) { c.WebRoot = "../web" }} {
		bad := c
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
	for _, value := range []string{"0", "-1", "4294967295", "2147483648", "not-id"} {
		if _, e := parseID(value); e == nil {
			t.Fatal(value)
		}
	}
	if !validDirectory("/var/tmp/andeiva-local-native001") || validDirectory("/var/lib/andeiva-preview") || validDirectory("/var/tmp/../tmp/andeiva-local-native001") {
		t.Fatal("directory scope")
	}
}
func testIDs(t *testing.T) identities {
	t.Helper()
	uid, e := parseID(strconvID(os.Getuid()))
	if e != nil {
		t.Skip("unprivileged test requires nonroot UID")
	}
	gid, e := parseID(strconvID(os.Getgid()))
	if e != nil {
		t.Skip("unprivileged test requires nonroot GID")
	}
	return identities{APIUID: uid, APIGID: gid}
}
func strconvID(v int) string { b, _ := json.Marshal(v); return string(b) }
func TestBootMarkerAndProtectedAudit(t *testing.T) {
	ids := testIDs(t)
	dir := t.TempDir()
	for _, d := range []string{"runtime", "audit", "state"} {
		if e := os.Mkdir(filepath.Join(dir, d), 0700); e != nil {
			t.Fatal(e)
		}
	}
	boot := "11111111-1111-1111-1111-111111111111"
	if b, e := bootRequired(dir, ids, boot); e != nil || !b {
		t.Fatal(b, e)
	}
	if e := markBoot(dir, ids, boot); e != nil {
		t.Fatal(e)
	}
	if b, e := bootRequired(dir, ids, boot); e != nil || b {
		t.Fatal("same-boot reset must retain Running", b, e)
	}
	if b, e := bootRequired(dir, ids, "22222222-2222-2222-2222-222222222222"); e != nil || !b {
		t.Fatal("OS boot selects Startup", b, e)
	}
	a, e := openAudit(dir, ids)
	if e != nil {
		t.Fatal(e)
	}
	if a.Append(adminauth.Event{At: time.Now(), Actor: "admin-a", Action: "login", Result: "ok"}) != nil {
		t.Fatal("append")
	}
	if a.Close() != nil {
		t.Fatal("close")
	}
	a, e = openAudit(dir, ids)
	if e != nil {
		t.Fatal(e)
	}
	a.size = auditBudget - 1
	if a.Append(adminauth.Event{At: time.Now()}) == nil || a.healthy() {
		t.Fatal("audit exhaustion must latch unavailable")
	}
	if a.Close() != nil {
		t.Fatal("close")
	}
	if e := os.Chmod(filepath.Join(dir, "runtime", "boot-id"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := bootRequired(dir, ids, boot); e == nil {
		t.Fatal("invalid permissions interpreted as a fresh boot")
	}
}
func TestProbeSelectorsAndFailureClassification(t *testing.T) {
	p := ProbeRequest{Side: "source", Family: "ipv6", Origin: "alternate", Protocol: "https", Port: 18080, Operation: "status", Username: "admin-a"}
	src, dst, network, e := p.addresses()
	if e != nil || src != "fd42:616e:6465:1::3" || dst != "[fd42:616e:6465:1::1]:18080" || network != "tcp6" {
		t.Fatal(src, dst, network, e)
	}
	p.Side = "host"
	if p.validate() == nil {
		t.Fatal("host target accepted")
	}
	if dialError(unix.ECONNREFUSED) != probeRefused {
		t.Fatal("refusal is not a deny observation")
	}
	if resultError(errors.New("credential should never escape")).Error != probeProtocol.Error() {
		t.Fatal("diagnostic leak")
	}
}
func TestHTTPSProbeValidatesCAAndAuthentication(t *testing.T) {
	ca, cert, key, _, _, e := certificates(testConfig())
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		t.Fatal(e)
	}
	token := strings.Repeat("a", 64)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/login":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
		case "/api/v1/auth/logout":
			_, _ = io.WriteString(w, "{}")
		default:
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.WriteHeader(401)
			}
			_, _ = io.WriteString(w, `{"snapshot":{"generation":7}}`)
		}
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	defer server.Close()
	p := probeLaunch{CA: ca, Request: ProbeRequest{Operation: "status", Session: token}}
	d := &net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}
	r := probeHTTPS(context.Background(), p, d, "tcp4", server.Listener.Addr().String())
	if r.Status != 200 || r.Error != "" {
		t.Fatal(r.Status, r.Error)
	}
	other, _, _, _, _, e := certificates(testConfig())
	if e != nil {
		t.Fatal(e)
	}
	p.CA = other
	if r := probeHTTPS(context.Background(), p, d, "tcp4", server.Listener.Addr().String()); r.Error != probeTLS.Error() {
		t.Fatal("untrusted peer was not TLS failure", r.Error)
	}
}

type probeBackend struct{ backendGate }

func (*probeBackend) Status(context.Context, localadmin.Context) (localadmin.Status, error) {
	return localadmin.Status{Snapshot: configpoc.Snapshot{Generation: 7}}, nil
}
func TestSSHProbePinsHostAndUsesRealLogin(t *testing.T) {
	_, _, _, private, public, e := certificates(testConfig())
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.ParsePrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	secret, _ := randomID()
	secret += secret
	sum := sha256.Sum256([]byte(secret))
	auth, e := adminauth.New([]adminauth.Account{{Username: "admin-a", Role: "admin", CredentialSHA256: hex.EncodeToString(sum[:])}}, func(adminauth.Event) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	addr := listener.Addr().(*net.TCPAddr)
	if addr.Port < 1024 || addr.Port > 65535 {
		t.Fatal("port")
	}
	server, e := localssh.New(localssh.Options{Auth: auth, Backend: &probeBackend{}, Listener: localpolicy.Listener{Owner: "management", Service: "ssh", Interface: "lo", LocalAddress: "127.0.0.1", Protocol: localpolicy.TCP, Port: uint16(addr.Port)}, ActivationHash: strings.Repeat("a", 64), HostKey: signer, Limits: localssh.NewLimits(), Audit: func(adminauth.Event) error { return nil }})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		if server.Close() != nil {
			t.Error("close")
		}
		if e := <-done; e != nil {
			t.Error(e)
		}
	}()
	_, token, e := auth.Login("admin-a", secret)
	if e != nil {
		t.Fatal(e)
	}
	p := probeLaunch{HostKey: public, Request: ProbeRequest{Username: "admin-a", Operation: "status", Session: token}}
	d := &net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}
	if r := probeSSH(context.Background(), p, d, "tcp4", listener.Addr().String()); r.Status != 200 {
		t.Fatal(r.Error)
	}
	_, _, _, _, other, e := certificates(testConfig())
	if e != nil {
		t.Fatal(e)
	}
	p.HostKey = other
	if r := probeSSH(context.Background(), p, d, "tcp4", listener.Addr().String()); r.Error != probeHostKey.Error() {
		t.Fatal("host pin not enforced", r.Error)
	}
}
func TestBackendGateAndLateEvents(t *testing.T) {
	g := &backendGate{}
	if _, e := g.Status(context.Background(), localadmin.Context{}); e == nil {
		t.Fatal("unrecovered backend accepted")
	}
	out := make(chan childEvent, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readEvents(ctx, "api", "old-instance", bytes.NewBufferString(`{"event":"ready"}`+"\n"), out, nil, cancel)
	if e := <-out; e.instance != "old-instance" {
		t.Fatal("event lost launch identity")
	}
}

func TestMissingOrCorruptBootMarkerNeverResetsJournal(t *testing.T) {
	ids := testIDs(t)
	dir := t.TempDir()
	for _, name := range []string{"runtime", "state"} {
		if os.Mkdir(filepath.Join(dir, name), 0700) != nil {
			t.Fatal("mkdir")
		}
	}
	boot := "11111111-1111-1111-1111-111111111111"
	if e := os.WriteFile(filepath.Join(dir, "state", "journal.jsonl"), []byte("existing durable journal"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := bootRequired(dir, ids, boot); e == nil {
		t.Fatal("missing marker with journal treated as new boot")
	}
	for _, bad := range []string{"", "truncated", strings.ToUpper(boot[:8]) + "-zzzz-1111-1111-111111111111"} {
		if os.WriteFile(filepath.Join(dir, "runtime", "boot-id"), []byte(bad), 0600) != nil {
			t.Fatal("write")
		}
		if _, e := bootRequired(dir, ids, boot); e == nil {
			t.Fatal("corrupt marker treated as reboot")
		}
	}
}

func TestSameBootRebuildRecoversRunningAndPending(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	ctx := context.Background()
	admin := configpoc.Principal{ID: "admin-a", Role: configpoc.RoleAdmin}
	initial := configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: nftfixture.LocalInventory()}}
	open := func(boot bool) *configpoc.Service {
		s, e := configpoc.Open(dir, []configpoc.Engine{configpoc.NewSimEngine("local-test-double")}, configpoc.Options{Initial: &initial, Boot: boot})
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	s := open(true)
	status := func() configpoc.Snapshot {
		v, e := s.Execute(ctx, admin, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	call := func(r configpoc.Request) configpoc.Snapshot {
		before := status()
		r.Key = fmt.Sprintf("request-%d-%s", before.Generation, r.Operation)
		r.ExpectedGeneration = before.Generation
		v, e := s.Execute(ctx, admin, configpoc.API, r)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	startup := status().Startup.Hash
	lan := nftfixture.LocalInventory()[0]
	service, e := localpolicy.DefaultManagement("management", "https", lan, "198.18.1.1", []string{"198.18.1.2/32"})
	if e != nil {
		t.Fatal(e)
	}
	service.Endpoints[0].FirstPort = 18080
	service.Endpoints[0].LastPort = 18080
	candidate := initial
	local := *initial.LocalServices
	local.Services = []localpolicy.Service{service}
	candidate.LocalServices = &local
	call(configpoc.Request{Operation: configpoc.OpStage, Config: &candidate})
	pending := call(configpoc.Request{Operation: configpoc.OpCommit, ConfirmFor: 30 * time.Second})
	call(configpoc.Request{Operation: configpoc.OpConfirm, Target: pending.Running.Hash})
	running := status().Running.Hash
	if s.Close() != nil {
		t.Fatal("close")
	}
	s = open(false)
	if status().Running.Hash != running || status().Startup.Hash != startup {
		t.Fatal("same-boot reset lost unsaved Running")
	}
	local.Services[0].Endpoints[0].FirstPort = 18081
	local.Services[0].Endpoints[0].LastPort = 18081
	call(configpoc.Request{Operation: configpoc.OpStage, Config: &candidate})
	call(configpoc.Request{Operation: configpoc.OpCommit, ConfirmFor: 30 * time.Second})
	if s.Close() != nil {
		t.Fatal("close")
	}
	s = open(false)
	if status().Pending != nil || status().Running.Hash != running {
		t.Fatal("pending reset did not restore verified previous")
	}
	if s.Close() != nil {
		t.Fatal("close")
	}
	s = open(true)
	defer s.Close()
	if status().Running.Hash != startup {
		t.Fatal("OS boot did not restore Startup")
	}
}

func TestRootProbeSessionRevokedAndNoDurableCredentialInHandoff(t *testing.T) {
	ca, cert, key, _, _, e := certificates(testConfig())
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		t.Fatal(e)
	}
	token := strings.Repeat("b", 64)
	revoked := false
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/login" {
			_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(401)
			return
		}
		revoked = true
		_, _ = io.WriteString(w, "{}")
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	defer server.Close()
	session, revoke, e := recoverySession(context.Background(), server.URL, ca, adminclient.Credentials{Username: "admin-a", Credential: "unit-only-secret"})
	if e != nil || session != token {
		t.Fatal(e)
	}
	data := encode(probeLaunch{Request: ProbeRequest{Session: session}})
	if bytes.Contains(data, []byte("credential")) || bytes.Contains(data, []byte("unit-only-secret")) {
		t.Fatal("durable secret reached handoff")
	}
	if e := revoke(); e != nil || !revoked {
		t.Fatal("session not revoked", e)
	}
}

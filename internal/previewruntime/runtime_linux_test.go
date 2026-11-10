//go:build linux

package previewruntime

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
)

func testConfig() Config {
	return Config{SchemaVersion: 1, ListenAddress: "192.168.18.254:9443", Interface: "ens34", AllowedCIDR: "192.168.18.1/32", APIUser: "andeiva-preview-api", HelperUser: "andeiva-preview-helper", IPCGroup: "andeiva-preview-ipc"}
}
func TestConfigBoundaries(t *testing.T) {
	c := testConfig()
	if c.Validate() != nil {
		t.Fatal("valid config denied")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.ListenAddress = "0.0.0.0:9443" }, func(c *Config) { c.ListenAddress = "[::1]:9443" }, func(c *Config) { c.AllowedCIDR = "192.168.18.1/24" }, func(c *Config) { c.Interface = "ens34\nX=1" }, func(c *Config) { c.IPCGroup = "" }, func(c *Config) { c.HelperUser = c.APIUser }} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("invalid config accepted: %+v", bad)
		}
	}
	if (Identities{SchemaVersion: 1, APIUID: 10, APIGID: 20, HelperUID: 11, IPCGID: 20}).Validate() == nil {
		t.Fatal("shared secrets group accepted")
	}
	m := Metadata{SchemaVersion: 1, RunID: strings.Repeat("a", 32), BootID: "11111111-1111-1111-1111-111111111111", HostNamespace: 1, GatewayNamespace: 2, SourceNamespace: 3, SinkNamespace: 4}
	if m.Validate() != nil {
		t.Fatal("valid metadata")
	}
	m.GatewayNamespace = m.HostNamespace
	if m.Validate() == nil {
		t.Fatal("host namespace accepted")
	}
}
func TestCertificateTrustNameAndExpiry(t *testing.T) {
	now := time.Now()
	ca, cert, key, e := certificates("192.168.18.254", now)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	options := x509.VerifyOptions{Roots: pool, DNSName: "192.168.18.254", CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if _, e = leaf.Verify(options); e != nil {
		t.Fatal(e)
	}
	options.DNSName = "127.0.0.1"
	if _, e = leaf.Verify(options); e == nil {
		t.Fatal("wrong host trusted")
	}
	options.DNSName = "192.168.18.254"
	options.CurrentTime = now.Add(366 * 24 * time.Hour)
	if _, e = leaf.Verify(options); e == nil {
		t.Fatal("expired trusted")
	}
}
func privateDir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if os.Chmod(p, 0700) != nil {
		t.Fatal("chmod")
	}
	return p
}
func TestBootMarkerCrashAndResume(t *testing.T) {
	p := privateDir(t)
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	first := "11111111-1111-1111-1111-111111111111"
	second := "22222222-2222-2222-2222-222222222222"
	fail := errors.New("recovery failed")
	if e := recoverBoot(p, first, uid, gid, func(boot bool) error {
		if !boot {
			t.Fatal("missing marker did not boot")
		}
		return fail
	}); !errors.Is(e, fail) {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(p, "boot.json")); !os.IsNotExist(e) {
		t.Fatal("marker written before barrier")
	}
	if e := recoverBoot(p, first, uid, gid, func(boot bool) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e := recoverBoot(p, first, uid, gid, func(boot bool) error {
		if boot {
			t.Fatal("same boot lost running")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	original, _ := os.ReadFile(filepath.Join(p, "boot.json"))
	if e := recoverBoot(p, second, uid, gid, func(boot bool) error {
		if !boot {
			t.Fatal("new boot kept running")
		}
		return fail
	}); !errors.Is(e, fail) {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(filepath.Join(p, "boot.json"))
	if string(original) != string(after) {
		t.Fatal("failed recovery advanced marker")
	}
	if e := os.WriteFile(filepath.Join(p, "boot.next"), marshal(bootMarker{Version: 1, BootID: second}), 0600); e != nil {
		t.Fatal(e)
	}
	if e := recoverBoot(p, second, uid, gid, func(bool) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(p, "boot.json"), []byte("bad"), 0600); e != nil {
		t.Fatal(e)
	}
	called := false
	if recoverBoot(p, second, uid, gid, func(bool) error { called = true; return nil }) == nil || called {
		t.Fatal("corrupt marker touched engine")
	}
}
func TestAuditQuotaRestartAndPreservation(t *testing.T) {
	p := privateDir(t)
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	a, e := openAuditBounded(p, uid, gid, 128, 2)
	if e != nil {
		t.Fatal(e)
	}
	event := adminauth.Event{At: time.Now().UTC(), Actor: "admin-a", Action: "login", Result: "ok"}
	if a.Append(event) != nil || a.Append(event) != nil {
		t.Fatal("initial append")
	}
	if a.Append(event) == nil {
		t.Fatal("quota not enforced")
	}
	a.Close()
	entries, _ := os.ReadDir(p)
	if len(entries) != 2 {
		t.Fatal("segments missing")
	}
	before, _ := os.ReadFile(filepath.Join(p, "000001.jsonl"))
	a, e = openAuditBounded(p, uid, gid, 128, 2)
	if e != nil {
		t.Fatal(e)
	}
	if a.Append(event) == nil {
		t.Fatal("restart bypassed quota")
	}
	a.Close()
	after, _ := os.ReadFile(filepath.Join(p, "000001.jsonl"))
	if string(before) != string(after) {
		t.Fatal("protected audit changed")
	}
	if os.WriteFile(filepath.Join(p, "000002.jsonl"), []byte("partial"), 0600) != nil {
		t.Fatal("write")
	}
	if a, e = openAuditBounded(p, uid, gid, 128, 2); e == nil {
		a.Close()
		t.Fatal("partial audit accepted")
	}
}
func TestOwnedFilesRejectLinksAndModes(t *testing.T) {
	p := privateDir(t)
	file := filepath.Join(p, "record")
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if os.WriteFile(file, []byte("ok"), 0600) != nil {
		t.Fatal("write")
	}
	if _, e := readOwned(file, uid, gid, 0600, 8); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(p, "link")
	if os.Symlink(file, link) != nil {
		t.Fatal("symlink")
	}
	if _, e := readOwned(link, uid, gid, 0600, 8); e == nil {
		t.Fatal("symlink accepted")
	}
	if os.Link(file, filepath.Join(p, "hard")) != nil {
		t.Fatal("hardlink")
	}
	if _, e := readOwned(file, uid, gid, 0600, 8); e == nil {
		t.Fatal("hardlink accepted")
	}
}
func TestSocketPeerAndListenerBoundary(t *testing.T) {
	p := privateDir(t)
	path := filepath.Join(p, "control.sock")
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	l, e := listenPrivate(path, uid, gid)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	defer os.Remove(path)
	accepted := make(chan *net.UnixConn, 1)
	go func() { c, _ := l.AcceptUnix(); accepted <- c }()
	client, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()
	if peer(server, uid, gid) != nil || peer(server, uid+1, gid) == nil {
		t.Fatal("peer credentials not enforced")
	}
	tcp, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	raw, _ := tcp.SyscallConn()
	var denied bool
	_ = raw.Control(func(fd uintptr) { denied = validateListener(int(fd), testConfig()) != nil })
	if !denied {
		t.Fatal("wrong listener accepted")
	}
	if inherited, e := inheritedListener(testConfig()); e == nil {
		inherited.Close()
		t.Fatal("missing activation accepted")
	}
}

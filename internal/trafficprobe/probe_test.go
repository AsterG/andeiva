package trafficprobe

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func configFor(t *testing.T, mode Mode, address string) Config {
	t.Helper()
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return Config{AuthorizedLab: true, Mode: mode, SourceIPv4: netip.MustParseAddr("127.0.0.1"), TargetIPv4: endpoint.Addr(), TargetPort: endpoint.Port(), Timeout: time.Second}
}

func TestTCPConnectAndSourceObservation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer := make(chan netip.AddrPort, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		address, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
		peer <- address
	}()
	result := Run(context.Background(), configFor(t, TCP, listener.Addr().String()))
	if result.Outcome != "connected" || !result.Observed() || len(result.Transports) != 1 || result.Transports[0].LocalPort == 0 {
		t.Fatalf("bad connection observation: %+v", result)
	}
	select {
	case address := <-peer:
		if address.Addr() != result.SourceIPv4 || address.Port() != result.Transports[0].LocalPort {
			t.Fatalf("source mismatch: %v %+v", address, result)
		}
	case <-time.After(time.Second):
		t.Fatal("no actual server connection")
	}
}

func TestUDPExactNonceAndNeutralTimeout(t *testing.T) {
	for _, mode := range []string{"exact", "altered", "oversized", "silent"} {
		t.Run(mode, func(t *testing.T) {
			server, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			seen := make(chan int, 1)
			go func() {
				var data [64]byte
				n, peer, err := server.ReadFrom(data[:])
				if err != nil {
					return
				}
				seen <- n
				switch mode {
				case "exact":
					_, _ = server.WriteTo(data[:n], peer)
				case "altered":
					data[0] ^= 1
					_, _ = server.WriteTo(data[:n], peer)
				case "oversized":
					_, _ = server.WriteTo(data[:n+1], peer)
				}
			}()
			cfg := configFor(t, UDP, server.LocalAddr().String())
			if mode == "silent" {
				cfg.Timeout = 100 * time.Millisecond
			}
			result := Run(context.Background(), cfg)
			want := "echo_mismatch"
			if mode == "exact" {
				want = "echo_verified"
			}
			if mode == "silent" {
				want = "timeout"
			}
			if result.Outcome != want || len(result.Transports) != 1 || result.Transports[0].BytesSent != 32 {
				t.Fatalf("unexpected UDP observation: %+v", result)
			}
			if result.Observed() != (mode == "exact") {
				t.Fatal("nonmatching or missing echo counted as success")
			}
			select {
			case n := <-seen:
				if n != 32 {
					t.Fatalf("wrong challenge size: %d", n)
				}
			case <-time.After(time.Second):
				t.Fatal("no actual datagram")
			}
		})
	}
}

func TestValidationRejectsBeforeTargetIOAndRedactsSecrets(t *testing.T) {
	valid := Config{AuthorizedLab: true, Mode: TCP, SourceIPv4: netip.MustParseAddr("127.0.0.1"), TargetIPv4: netip.MustParseAddr("127.0.0.1"), TargetPort: 9, Timeout: time.Second}
	cases := map[string]func(*Config){
		"missing-ack":           func(c *Config) { c.AuthorizedLab = false },
		"port-zero":             func(c *Config) { c.TargetPort = 0 },
		"zero-timeout":          func(c *Config) { c.Timeout = 0 },
		"long-timeout":          func(c *Config) { c.Timeout = MaxTimeout + 1 },
		"negative-timeout":      func(c *Config) { c.Timeout = -time.Second },
		"source-unspecified":    func(c *Config) { c.SourceIPv4 = netip.IPv4Unspecified() },
		"mapped-source":         func(c *Config) { c.SourceIPv4 = netip.MustParseAddr("::ffff:127.0.0.1") },
		"multicast-target":      func(c *Config) { c.TargetIPv4 = netip.MustParseAddr("224.0.0.1") },
		"broadcast-target":      func(c *Config) { c.TargetIPv4 = netip.MustParseAddr("255.255.255.255") },
		"source-ipv6":           func(c *Config) { c.SourceIPv4 = netip.IPv6Loopback() },
		"unknown-mode":          func(c *Config) { c.Mode = "SECRET_MODE" },
		"wrong-mode-field":      func(c *Config) { c.URL = "SECRET_URL" },
		"dns-literal":           func(c *Config) { c.Mode = DNS; c.DNSName = "127.0.0.1" },
		"dns-ambiguous-numeric": func(c *Config) { c.Mode = DNS; c.DNSName = "127.1" },
		"dns-overlong-label":    func(c *Config) { c.Mode = DNS; c.DNSName = strings.Repeat("a", 64) + ".example" },
		"url-userinfo":          func(c *Config) { c.Mode = HTTP; c.URL = "http://user:SECRET_PASSWORD@127.0.0.1:9/" },
		"url-query":             func(c *Config) { c.Mode = HTTP; c.URL = "http://127.0.0.1:9/?token=SECRET_QUERY" },
		"url-fragment":          func(c *Config) { c.Mode = HTTP; c.URL = "http://127.0.0.1:9/#SECRET_FRAGMENT" },
		"url-empty-query":       func(c *Config) { c.Mode = HTTP; c.URL = "http://127.0.0.1:9/?" },
		"url-wrong-port":        func(c *Config) { c.Mode = HTTP; c.URL = "http://127.0.0.1:80/" },
		"url-ambiguous-port":    func(c *Config) { c.Mode = HTTP; c.TargetPort = 80; c.URL = "http://probe.example:/" },
		"url-literal-mismatch":  func(c *Config) { c.Mode = HTTP; c.URL = "http://192.0.2.1:9/" },
		"url-ambiguous-literal": func(c *Config) { c.Mode = HTTP; c.URL = "http://127.1:9/" },
		"ca-for-http":           func(c *Config) { c.Mode = HTTP; c.URL = "http://127.0.0.1:9/"; c.CAFile = "/tmp/ca.pem" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			change(&cfg)
			result := Run(context.Background(), cfg)
			if result.Outcome != "invalid_configuration" || len(result.Transports) != 0 || result.Observed() {
				t.Fatalf("invalid config performed probe: %+v", result)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "SECRET") {
				t.Fatal("invalid input leaked to result")
			}
		})
	}
}

func TestCancellationIsNeutral(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := Run(ctx, Config{AuthorizedLab: true, Mode: TCP, SourceIPv4: netip.MustParseAddr("127.0.0.1"), TargetIPv4: netip.MustParseAddr("127.0.0.1"), TargetPort: 9, Timeout: time.Second})
	if result.Outcome != "canceled" || result.Observed() || len(result.Transports) != 0 {
		t.Fatalf("bad cancellation: %+v", result)
	}
}

func TestCancelDuringUDPIO(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		var b [64]byte
		if _, _, err := server.ReadFrom(b[:]); err == nil {
			cancel()
		}
	}()
	result := Run(ctx, configFor(t, UDP, server.LocalAddr().String()))
	if result.Outcome != "canceled" || result.Observed() {
		t.Fatalf("canceled read was misclassified: %+v", result)
	}
}

func TestCancelDuringDNSIO(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		var data [4096]byte
		if _, _, err := server.ReadFrom(data[:]); err == nil {
			cancel()
		}
	}()
	cfg := configFor(t, DNS, server.LocalAddr().String())
	cfg.DNSName = "probe.example"
	result := Run(ctx, cfg)
	if result.Outcome != "canceled" || result.Observed() {
		t.Fatalf("DNS cancellation misclassified: %+v", result)
	}
}

func TestHTTPUsesExplicitEndpointWithoutProxyOrRedirect(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodHead || !strings.HasPrefix(r.Host, "probe.example:") {
			t.Errorf("wrong request: %s %s", r.Method, r.Host)
		}
		w.Header().Set("Location", "http://other.invalid:9/SECRET_LOCATION")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	cfg := configFor(t, HTTP, server.Listener.Addr().String())
	// Use the selected local port with a DNS-looking origin; no lookup is needed.
	cfg.URL = "http://probe.example:" + strings.Split(server.Listener.Addr().String(), ":")[1] + "/"
	result := Run(context.Background(), cfg)
	if result.Outcome != "http_response" || result.HTTPStatus != http.StatusFound || result.TLSVerified || calls.Load() != 1 || len(result.Transports) != 1 {
		t.Fatalf("proxy or redirect escaped endpoint: %+v calls=%d", result, calls.Load())
	}
}

func certificateFile(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trusted-fixture.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func tlsServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Error("not HEAD")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestHTTPSVerifiesCAAndHostname(t *testing.T) {
	server := tlsServer(t)
	base := configFor(t, HTTP, server.Listener.Addr().String())
	base.URL = server.URL
	trusted := certificateFile(t, server)
	for _, mode := range []string{"trusted", "unknown-ca", "wrong-host"} {
		t.Run(mode, func(t *testing.T) {
			cfg := base
			if mode != "unknown-ca" {
				cfg.CAFile = trusted
			}
			if mode == "wrong-host" {
				cfg.URL = "https://wrong.invalid:" + strings.Split(server.Listener.Addr().String(), ":")[1] + "/"
			}
			result := Run(context.Background(), cfg)
			if mode == "trusted" {
				if result.Outcome != "http_response" || !result.TLSVerified || result.HTTPStatus != http.StatusNoContent {
					t.Fatalf("verified HTTPS failed: %+v", result)
				}
			} else if result.Outcome != "tls_verification_failed" || result.Observed() || result.TLSVerified {
				t.Fatalf("accepted unverified HTTPS: %+v", result)
			}
		})
	}
}

func TestHTTPHeaderBound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Large", strings.Repeat("x", 20*1024))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := configFor(t, HTTP, server.Listener.Addr().String())
	cfg.URL = server.URL
	result := Run(context.Background(), cfg)
	if result.Outcome != "unavailable" || result.Observed() {
		t.Fatalf("oversized headers accepted: %+v", result)
	}
}

func dnsResponse(query []byte, truncated bool) []byte {
	end := 12
	for end < len(query) && query[end] != 0 {
		end += int(query[end]) + 1
	}
	end += 5
	if len(query) < 12 || end > len(query) {
		return nil
	}
	response := make([]byte, 12)
	copy(response[:2], query[:2])
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[4:6], 1)
	response = append(response, query[12:end]...)
	if truncated {
		binary.BigEndian.PutUint16(response[2:4], 0x8380)
		return response
	}
	binary.BigEndian.PutUint16(response[6:8], 1)
	return append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 198, 51, 100, 9)
}

func TestDNSExplicitServerAndObservedTCPFallback(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "udp-then-tcp"}[fallback], func(t *testing.T) {
			tcp, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			udp, err := net.ListenPacket("udp4", tcp.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			go func() {
				var b [4096]byte
				n, peer, err := udp.ReadFrom(b[:])
				if err == nil {
					_, _ = udp.WriteTo(dnsResponse(b[:n], fallback), peer)
				}
			}()
			if fallback {
				go func() {
					conn, err := tcp.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(time.Second))
					var size [2]byte
					if _, err := io.ReadFull(conn, size[:]); err != nil {
						return
					}
					length := binary.BigEndian.Uint16(size[:])
					if length > 4096 {
						return
					}
					query := make([]byte, length)
					if _, err := io.ReadFull(conn, query); err != nil {
						return
					}
					reply := dnsResponse(query, false)
					binary.BigEndian.PutUint16(size[:], uint16(len(reply)))
					_, _ = conn.Write(append(size[:], reply...))
				}()
			}
			cfg := configFor(t, DNS, tcp.Addr().String())
			cfg.DNSName = "probe.example"
			result := Run(context.Background(), cfg)
			if result.Outcome != "resolved_with_dns_io" || result.ResolutionSource != "unattributed" || len(result.ResolvedIPv4) != 1 || result.ResolvedIPv4[0] != netip.MustParseAddr("198.51.100.9") {
				t.Fatalf("DNS probe failed: %+v", result)
			}
			want := 1
			if fallback {
				want = 2
			}
			if len(result.Transports) != want || result.Transports[0].Protocol != "udp" {
				t.Fatalf("wrong actual DNS transport count: %+v", result)
			}
			for i, transport := range result.Transports {
				if !transport.Connected || transport.BytesSent == 0 || transport.BytesReceived == 0 || transport.LocalPort == 0 {
					t.Fatalf("no actual IO: %+v", transport)
				}
				if i == 1 && transport.Protocol != "tcp" {
					t.Fatal("fallback not recorded")
				}
			}
		})
	}
}

func TestDNSNegativeResponseThenSimulatedNSSFallbackIsUnattributed(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	served := make(chan struct{}, 1)
	go func() {
		var query [4096]byte
		n, peer, err := server.ReadFrom(query[:])
		if err != nil {
			return
		}
		reply := dnsResponse(query[:n], true)
		if len(reply) < 12 {
			return
		}
		binary.BigEndian.PutUint16(reply[2:4], 0x8183)
		if _, err := server.WriteTo(reply, peer); err == nil {
			served <- struct{}{}
		}
	}()
	cfg := configFor(t, DNS, server.LocalAddr().String())
	cfg.DNSName = fmt.Sprintf("nss-fallback-%d.example", time.Now().UnixNano())
	observed := new(trace)
	resolver := net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return observed.dial(ctx, cfg, network)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	localValue := netip.MustParseAddr("192.0.2.44")
	resolve := func(ctx context.Context, network, name string) ([]net.IP, error) {
		_, err := resolver.LookupIP(ctx, network, name)
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			t.Errorf("fixture did not return NXDOMAIN: %v", err)
			return nil, errInvalid
		}
		// This controlled seam models NSS dns/files fallback; system hosts and
		// resolver configuration are never changed by the test.
		return []net.IP{net.IP(localValue.AsSlice())}, nil
	}
	addresses, outcome := lookupWithResolver(ctx, cfg, observed, resolve)
	if outcome != "resolved_with_dns_io" || len(addresses) != 1 || addresses[0] != localValue {
		t.Fatalf("fallback resolution lost or attributed as a DNS answer: %s %v", outcome, addresses)
	}
	if len(observed.snapshot()) != 1 || observed.snapshot()[0].BytesReceived == 0 {
		t.Fatal("negative DNS I/O was not actually observed")
	}
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("NXDOMAIN server was not used")
	}
}

func TestDNSLocalResolutionWithoutIODoesNotProveServer(t *testing.T) {
	cfg := Config{DNSName: "local.example"}
	resolve := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.44")}, nil
	}
	addresses, outcome := lookupWithResolver(context.Background(), cfg, new(trace), resolve)
	if outcome != "dns_not_observed" || len(addresses) != 0 {
		t.Fatalf("unobserved local resolution counted as DNS I/O: %s %v", outcome, addresses)
	}
}

func TestCAPermissionsLinksAndBoundsFailBeforeDial(t *testing.T) {
	server := tlsServer(t)
	trusted := certificateFile(t, server)
	for _, mode := range []string{"invalid", "oversized", "writable", "symlink", "ancestor-symlink", "directory"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ca.pem")
			switch mode {
			case "invalid":
				if err := os.WriteFile(path, []byte("not PEM"), 0600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(path, make([]byte, maxCABytes+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "writable":
				data, err := os.ReadFile(trusted)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(trusted, path); err != nil {
					t.Fatal(err)
				}
			case "ancestor-symlink":
				if err := os.Symlink(filepath.Dir(trusted), filepath.Join(dir, "linked")); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(dir, "linked", filepath.Base(trusted))
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			cfg := configFor(t, HTTP, server.Listener.Addr().String())
			cfg.URL = server.URL
			cfg.CAFile = path
			result := Run(context.Background(), cfg)
			if result.Outcome != "invalid_ca_file" || len(result.Transports) != 0 || result.Observed() {
				t.Fatalf("unsafe trust source used: %+v", result)
			}
		})
	}
}

func BenchmarkInvalidProbe(b *testing.B) {
	for b.Loop() {
		if result := Run(context.Background(), Config{}); result.Outcome != "invalid_configuration" {
			b.Fatal(result)
		}
	}
}

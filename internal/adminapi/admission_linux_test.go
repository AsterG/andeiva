//go:build linux

package adminapi

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Real loopback sockets and verified TLS exercise the transport's peer address;
// no host interfaces, routes, firewall rules or privileged namespaces are changed.
func originClient(t *testing.T, f *fixtureAPI, source string) *http.Client {
	t.Helper()
	transport := f.server.Client().Transport.(*http.Transport).Clone()
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("verified test-server TLS is required")
	}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	}
	transport.Proxy = nil
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func originLogin(t *testing.T, f *fixtureAPI, client *http.Client, credential string, headers map[string]string) int {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, f.server.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"alice","credential":"`+credential+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-ANDEIVA-Client", "api")
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err = io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode
}

func TestLoginOriginFloodCannotBlockVerifiedHTTPS(t *testing.T) {
	f := fixtureServer(t, "admin")
	a := originClient(t, f, "127.0.0.2")
	b := originClient(t, f, "127.0.0.3")
	// Exact one-second quotas are covered by deterministic manager tests. Real
	// TLS requests may span a window under load; every invalid attempt must
	// remain rejected and neither source may starve verified credentials.
	for i := 0; i < 4; i++ {
		if code := originLogin(t, f, a, strings.Repeat("0", 64), nil); code != http.StatusUnauthorized && code != http.StatusTooManyRequests {
			t.Fatalf("invalid login %d: status %d", i, code)
		}
	}
	if code := originLogin(t, f, a, strings.Repeat("0", 64), nil); code != http.StatusTooManyRequests && code != http.StatusUnauthorized {
		t.Fatalf("anonymous budget: status %d", code)
	}
	if code := originLogin(t, f, b, f.secret, nil); code != http.StatusOK {
		t.Fatalf("anonymous peer exhausted verified HTTPS budget: status %d", code)
	}
	if code := originLogin(t, f, a, f.secret, nil); code != http.StatusOK {
		t.Fatalf("shared source cannot authenticate valid credentials: status %d", code)
	}
}

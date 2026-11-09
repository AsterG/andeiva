package httpserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandlerBoundary(t *testing.T) {
	tests := []struct {
		method string
		path   string
		status int
		body   string
	}{
		{"GET", "/healthz", 200, "{\"status\":\"ok\"}\n"},
		{"HEAD", "/healthz", 200, ""},
		{"POST", "/healthz", 405, "{\"code\":\"ANDEIVA_METHOD_NOT_ALLOWED\"}\n"},
		{"OPTIONS", "/healthz", 405, "{\"code\":\"ANDEIVA_METHOD_NOT_ALLOWED\"}\n"},
		{"GET", "/healthz/", 404, "{\"code\":\"ANDEIVA_NOT_FOUND\"}\n"},
		{"GET", "/healthz?detail=1", 404, "{\"code\":\"ANDEIVA_NOT_FOUND\"}\n"},
		{"GET", "/%68ealthz", 404, "{\"code\":\"ANDEIVA_NOT_FOUND\"}\n"},
		{"GET", "/admin", 404, "{\"code\":\"ANDEIVA_NOT_FOUND\"}\n"},
		{"GET", "/", 404, "{\"code\":\"ANDEIVA_NOT_FOUND\"}\n"},
		{"HEAD", "/admin", 404, ""},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			Handler().ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, nil))
			if recorder.Code != test.status || recorder.Body.String() != test.body {
				t.Fatalf("response: %d %q", recorder.Code, recorder.Body.String())
			}
			if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("missing response protections: %v", recorder.Header())
			}
			if test.status == 405 && recorder.Header().Get("Allow") != "GET, HEAD" {
				t.Fatal("missing permitted methods")
			}
		})
	}
}

func TestParseAddress(t *testing.T) {
	for _, value := range []string{"", "127.0.0.1:4000", "0.0.0.0:4000", "[::1]:4000", "[::]:4000"} {
		address, err := ParseAddress(value)
		if err != nil || address == "" {
			t.Fatalf("valid address %q: %q, %v", value, address, err)
		}
		if value == "" && address != "127.0.0.1:4000" {
			t.Fatalf("default listener is not loopback: %q", address)
		}
	}
	for _, value := range []string{":4000", "localhost:4000", "127.0.0.1:0", "127.0.0.1:65536", "https://127.0.0.1:4000", "127.0.0.1:4000\n", "[fe80::1%eth0]:4000"} {
		if _, err := ParseAddress(value); err == nil {
			t.Fatalf("accepted invalid address %q", value)
		}
	}
}

func TestServeLifecycle(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Serve(ctx, listener) }()
	if err := Probe(context.Background(), listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("server did not stop")
	}
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err == nil {
		connection.Close()
		t.Fatal("listener remains open after shutdown")
	}
}

func TestServeListenerFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	if err := Serve(context.Background(), listener); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected listener error, got %v", err)
	}
}

func TestProbeRejectsNonLocalTargets(t *testing.T) {
	for _, address := range []string{"example.invalid:4000", "192.0.2.1:4000", "[2001:db8::1]:4000", "[fe80::1%eth0]:4000", "127.0.0.1:0"} {
		if err := Probe(context.Background(), address); err == nil || err.Error() != "ANDEIVA_INVALID_PROBE_ADDRESS" {
			t.Fatalf("target %q: %v", address, err)
		}
	}
}

func TestProbeIgnoresProxyAndMapsWildcard(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:4000")
	t.Setenv("http_proxy", "http://192.0.2.1:4000")
	server := httptest.NewServer(Handler())
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := Probe(context.Background(), "0.0.0.0:"+port); err != nil {
		t.Fatalf("local probe failed: %v", err)
	}
}

func TestProbeCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Probe(ctx, "127.0.0.1:4000"); err == nil {
		t.Fatal("canceled probe succeeded")
	}
}

func TestProbeResponseValidation(t *testing.T) {
	for _, test := range []struct {
		status int
		body   string
	}{
		{500, "{\"status\":\"ok\"}\n"},
		{200, "<html>not ready</html>"},
		{200, strings.Repeat("a", 128)},
		{302, ""},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				t.Errorf("unexpected request %q", r.URL.Path)
			}
			w.Header().Set("Location", "http://192.0.2.1:4000/")
			w.WriteHeader(test.status)
			io.WriteString(w, test.body)
		}))
		err := Probe(context.Background(), strings.TrimPrefix(server.URL, "http://"))
		server.Close()
		if err == nil {
			t.Fatalf("accepted response %d %q", test.status, test.body)
		}
	}
}

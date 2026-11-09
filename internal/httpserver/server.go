// Package httpserver provides the development scaffold liveness endpoint.
package httpserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"
)

const DefaultAddress = "127.0.0.1:4000"

// ParseAddress rejects hostnames and ambiguous addresses. Non-loopback binding
// is an explicit development-only choice; authentication and TLS are not built.
func ParseAddress(value string) (string, error) {
	if value == "" {
		return DefaultAddress, nil
	}
	address, err := netip.ParseAddrPort(value)
	if err != nil || address.Port() == 0 || address.Addr().Zone() != "" {
		return "", errors.New("ANDEIVA_INVALID_LISTEN_ADDRESS")
	}
	return address.String(), nil
}

// Handler reports process liveness only, never inspection or gateway readiness.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		status := http.StatusOK
		body := "{\"status\":\"ok\"}\n"
		switch {
		case r.URL.EscapedPath() != "/healthz" || r.URL.RawQuery != "":
			status, body = http.StatusNotFound, "{\"code\":\"ANDEIVA_NOT_FOUND\"}\n"
		case r.Method != http.MethodGet && r.Method != http.MethodHead:
			w.Header().Set("Allow", "GET, HEAD")
			status, body = http.StatusMethodNotAllowed, "{\"code\":\"ANDEIVA_METHOD_NOT_ALLOWED\"}\n"
		}
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(body))
		}
	})
}

// Serve owns listener and drains active requests when ctx is canceled.
func Serve(ctx context.Context, listener net.Listener) error {
	server := &http.Server{
		Handler:           Handler(),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 * 1024,
	}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			<-result
			return err
		}
		err := <-result
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

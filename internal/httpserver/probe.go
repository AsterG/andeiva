package httpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"
)

// Probe checks only a local scaffold listener. Proxy settings and redirects are
// deliberately ignored so a container health check cannot contact another host.
func Probe(ctx context.Context, address string) error {
	target, err := netip.ParseAddrPort(address)
	if err != nil || target.Port() == 0 || target.Addr().Zone() != "" {
		return errors.New("ANDEIVA_INVALID_PROBE_ADDRESS")
	}
	if target.Addr().IsUnspecified() {
		loopback := netip.MustParseAddr("127.0.0.1")
		if target.Addr().Is6() {
			loopback = netip.IPv6Loopback()
		}
		target = netip.AddrPortFrom(loopback, target.Port())
	}
	if !target.Addr().IsLoopback() {
		return errors.New("ANDEIVA_INVALID_PROBE_ADDRESS")
	}
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target.String()+"/healthz", nil)
	if err != nil {
		return errors.New("ANDEIVA_HEALTHCHECK_FAILED")
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("ANDEIVA_HEALTHCHECK_FAILED: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64))
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "{\"status\":\"ok\"}\n" {
		return errors.New("ANDEIVA_HEALTHCHECK_FAILED")
	}
	return nil
}

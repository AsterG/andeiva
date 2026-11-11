package trafficprobe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Run makes observations, never Allow/Deny or NAT attribution. Configuration and
// source ownership are checked before opening a connection to the target.
func Run(parent context.Context, c Config) (result Result) {
	started := time.Now()
	result = Result{SchemaVersion: 1, StartedAtUTC: started.UTC(), Outcome: "invalid_configuration", Transports: []Transport{}}
	defer func() { result.ElapsedMicros = time.Since(started).Microseconds() }()
	origin, err := validate(c)
	if err != nil {
		return result
	}
	result.Mode, result.SourceIPv4, result.TargetIPv4, result.TargetPort = c.Mode, c.SourceIPv4, c.TargetIPv4, c.TargetPort
	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()
	if err := localSource(ctx, c.SourceIPv4); err != nil {
		result.Outcome = failure(ctx, err)
		return result
	}
	observed := new(trace)
	defer func() { result.Transports = observed.snapshot() }()
	switch c.Mode {
	case TCP:
		conn, err := observed.dial(ctx, c, "tcp")
		if err != nil {
			result.Outcome = failure(ctx, err)
			return result
		}
		if err := conn.Close(); err != nil {
			result.Outcome = failure(ctx, err)
			return result
		}
		result.Outcome = "connected"
	case UDP:
		result.Outcome = echo(ctx, c, observed)
	case DNS:
		result.ResolutionSource = "unattributed"
		result.ResolvedIPv4, result.Outcome = lookup(ctx, c, observed)
	case HTTP:
		result.Scheme = origin.Scheme
		result.HTTPStatus, result.TLSVerified, result.Outcome = head(ctx, c, origin, observed)
	}
	return result
}

func failure(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		return "tls_verification_failed"
	}
	return "unavailable"
}

func echo(ctx context.Context, c Config, observed *trace) string {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "unavailable"
	}
	conn, err := observed.dial(ctx, c, "udp")
	if err != nil {
		return failure(ctx, err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return "unavailable"
	}
	if n, err := conn.Write(nonce[:]); err != nil || n != len(nonce) {
		return failure(ctx, err)
	}
	var reply [33]byte
	n, err := conn.Read(reply[:])
	if err != nil {
		return failure(ctx, err)
	}
	if n != len(nonce) || !bytes.Equal(nonce[:], reply[:n]) {
		return "echo_mismatch"
	}
	return "echo_verified"
}

func lookup(ctx context.Context, c Config, observed *trace) ([]netip.Addr, string) {
	resolver := net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "udp" && network != "tcp" {
			return nil, errInvalid
		}
		return observed.dial(ctx, c, network)
	}}
	return lookupWithResolver(ctx, c, observed, resolver.LookupIP)
}

// Resolver success plus DNS I/O does not establish where the returned values
// came from: NSS can fall back to local files after a negative DNS response.
func lookupWithResolver(ctx context.Context, c Config, observed *trace, resolve func(context.Context, string, string) ([]net.IP, error)) ([]netip.Addr, string) {
	ips, err := resolve(ctx, "ip4", strings.TrimSuffix(c.DNSName, ".")+".")
	if err != nil {
		return nil, failure(ctx, err)
	}
	if len(ips) == 0 || len(ips) > MaxAnswers {
		return nil, "resolution_result_limit"
	}
	hadIO := false
	for _, item := range observed.snapshot() {
		hadIO = hadIO || item.BytesSent > 0 && item.BytesReceived > 0
	}
	if !hadIO {
		return nil, "dns_not_observed"
	}
	resolved := make([]netip.Addr, 0, len(ips))
	for _, raw := range ips {
		ip, ok := netip.AddrFromSlice(raw)
		if !ok || !ip.Unmap().Is4() {
			return nil, "resolution_result_invalid"
		}
		resolved = append(resolved, ip.Unmap())
	}
	slices.SortFunc(resolved, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(resolved), "resolved_with_dns_io"
}

func head(ctx context.Context, c Config, origin *url.URL, observed *trace) (int, bool, string) {
	var rootsConfig *tls.Config
	if origin.Scheme == "https" {
		rootsConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: origin.Hostname(), NextProtos: []string{"http/1.1"}}
		if c.CAFile != "" {
			pool, err := readCA(c.CAFile)
			if err != nil {
				return 0, false, "invalid_ca_file"
			}
			rootsConfig.RootCAs = pool
		}
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false,
		TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSClientConfig: rootsConfig, MaxResponseHeaderBytes: 16 * 1024,
		ResponseHeaderTimeout: c.Timeout, TLSHandshakeTimeout: c.Timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if len(observed.snapshot()) != 0 {
				return nil, errInvalid
			}
			return observed.dial(ctx, c, "tcp")
		},
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, origin.String(), nil)
	if err != nil {
		return 0, false, "invalid_configuration"
	}
	request.Header.Set("User-Agent", "ANDEIVA-Lab-Probe/1")
	response, err := client.Do(request)
	if err != nil {
		return 0, false, failure(ctx, err)
	}
	if err := response.Body.Close(); err != nil {
		return 0, false, "unavailable"
	}
	verified := response.TLS != nil && response.TLS.HandshakeComplete && len(response.TLS.VerifiedChains) > 0
	if origin.Scheme == "https" && !verified {
		return 0, false, "tls_verification_failed"
	}
	return response.StatusCode, verified, "http_response"
}

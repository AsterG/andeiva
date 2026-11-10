//go:build linux

package localruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"github.com/AsterG/andeiva/internal/adminclient"
	"io"
	"net/http"
	"time"
)

// The supervisor calls only its fixed retained recovery endpoint. Long-lived
// operator credentials never cross into the same-UID probe process.
func recoverySession(parent context.Context, origin string, ca []byte, credentials adminclient.Credentials) (string, func() error, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return "", nil, probeTLS
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 8192, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return probeProtocol }}
	call := func(ctx context.Context, path string, body any, token string) ([]byte, error) {
		r, e := http.NewRequestWithContext(ctx, "POST", origin+path, bytes.NewReader(encode(body)))
		if e != nil {
			return nil, probeProtocol
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-ANDEIVA-Client", "api")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response, e := client.Do(r)
		if e != nil {
			return nil, probeAuth
		}
		defer response.Body.Close()
		b, e := io.ReadAll(io.LimitReader(response.Body, 8193))
		if e != nil || len(b) > 8192 || response.StatusCode != 200 {
			return nil, probeAuth
		}
		return b, nil
	}
	data, e := call(parent, "/api/v1/auth/login", credentials, "")
	if e != nil {
		transport.CloseIdleConnections()
		return "", nil, e
	}
	var reply struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(data, &reply) != nil {
		transport.CloseIdleConnections()
		return "", nil, probeAuth
	}
	token, e := hex.DecodeString(reply.Token)
	if e != nil || len(token) != 32 || hex.EncodeToString(token) != reply.Token {
		transport.CloseIdleConnections()
		return "", nil, probeAuth
	}
	revoke := func() error {
		defer transport.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
		defer cancel()
		_, e := call(ctx, "/api/v1/auth/logout", struct{}{}, reply.Token)
		return e
	}
	return reply.Token, revoke, nil
}

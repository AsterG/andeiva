// Package adminclient implements the bounded HTTPS transport for the official CLI.
package adminclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
)

var (
	ErrConfiguration = errors.New("ANDEIVA_CLIENT_CONFIGURATION")
	ErrCredentials   = errors.New("ANDEIVA_CLIENT_CREDENTIALS")
	ErrTransport     = errors.New("ANDEIVA_CLIENT_TRANSPORT")
	ErrResponse      = errors.New("ANDEIVA_CLIENT_RESPONSE")
)

type Credentials struct {
	Username   string `json:"username"`
	Credential string `json:"credential"`
}
type APIError struct {
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
}

func (e *APIError) Error() string { return e.Code }

type History struct {
	Revisions  []configpoc.RevisionEntry `json:"revisions"`
	Audit      []configpoc.Audit         `json:"audit"`
	NextBefore uint64                    `json:"next_before"`
}
type Client struct {
	base  string
	http  *http.Client
	token string
}

func New(base string, caPEM []byte) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(caPEM) == 0 || len(caPEM) > 1024*1024 {
		return nil, ErrConfiguration
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, ErrConfiguration
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 12 * time.Second, MaxResponseHeaderBytes: 16384, DisableKeepAlives: true}
	return &Client{base: base, http: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrTransport }}}, nil
}

func ReadCredentials(path string) (Credentials, error) {
	f, err := openCredentials(path)
	if err != nil {
		return Credentials{}, ErrCredentials
	}
	defer f.Close()
	var result Credentials
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return Credentials{}, ErrCredentials
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || d.Decode(new(any)) != io.EOF || result.Username == "" || len(result.Username) > 64 || len(result.Credential) != 64 {
		return Credentials{}, ErrCredentials
	}
	return result, nil
}
func ReadCA(path string) ([]byte, error) {
	// #nosec G304 -- Explicit local CLI operator path, never HTTP input; regular files only, with a 1 MiB read bound.
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return nil, ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return nil, ErrConfiguration
	}
	return data, nil
}
func (c *Client) Login(ctx context.Context, credentials Credentials) (adminauth.Identity, error) {
	if c.token != "" {
		return adminauth.Identity{}, ErrConfiguration
	}
	var result struct {
		adminauth.Identity
		Token string `json:"token"`
	}
	if err := c.call(ctx, http.MethodPost, "/api/v1/auth/login", credentials, &result); err != nil {
		return adminauth.Identity{}, err
	}
	if len(result.Token) != 64 {
		return adminauth.Identity{}, ErrResponse
	}
	c.token = result.Token
	return result.Identity, nil
}
func (c *Client) Logout(ctx context.Context) error {
	if c.token == "" {
		return nil
	}
	defer func() { c.token = "" }()
	var result struct {
		LoggedOut bool `json:"logged_out"`
	}
	return c.call(ctx, http.MethodPost, "/api/v1/auth/logout", struct{}{}, &result)
}
func (c *Client) State(ctx context.Context) (adminapi.State, error) {
	var state adminapi.State
	err := c.call(ctx, http.MethodGet, "/api/v1/firewall", nil, &state)
	return state, err
}
func (c *Client) Execute(ctx context.Context, request configpoc.Request) (adminapi.State, error) {
	var state adminapi.State
	err := c.call(ctx, http.MethodPost, "/api/v1/firewall/transactions", request, &state)
	return state, err
}
func (c *Client) History(ctx context.Context, before uint64, limit int) (History, error) {
	if limit < 1 || limit > 100 {
		return History{}, ErrConfiguration
	}
	query := url.Values{}
	query.Set("before", jsonNumber(before))
	query.Set("limit", jsonNumber(uint64(limit)))
	var history History
	err := c.call(ctx, http.MethodGet, "/api/v1/firewall/history?"+query.Encode(), nil, &history)
	return history, err
}
func jsonNumber(n uint64) string { b, _ := json.Marshal(n); return string(b) }
func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil || len(data) > 65536 {
			return ErrConfiguration
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(data))
	if err != nil {
		return ErrConfiguration
	}
	req.Header.Set("X-ANDEIVA-Client", "cli")
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return ErrTransport
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 || response.Header.Get("Content-Type") != "application/json" {
		return ErrResponse
	}
	if response.StatusCode != http.StatusOK {
		var e APIError
		if json.Unmarshal(data, &e) != nil || !safeCode(e.Code) || !safeID(e.RequestID) {
			return ErrResponse
		}
		return &e
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrResponse
	}
	return nil
}
func safeCode(code string) bool {
	if !strings.HasPrefix(code, "ANDEIVA_") || len(code) > 80 {
		return false
	}
	for _, r := range code {
		if r != '_' && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}
func safeID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

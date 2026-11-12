// Package adminapi serves authenticated, same-origin laboratory administration.
package adminapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalltraffic"
	"github.com/AsterG/andeiva/internal/localadmin"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/productinfo"
)

const cookieName = "__Host-andeiva-session"

type Backend interface {
	Execute(context.Context, configpoc.Principal, configpoc.Surface, configpoc.Request) (configpoc.Snapshot, error)
	History(configpoc.Principal, uint64, int) ([]configpoc.RevisionEntry, error)
	Audit(configpoc.Principal) ([]configpoc.Audit, error)
}
type RuleCounter = firewalltraffic.Counter
type Effective struct {
	Revision     string        `json:"revision"`
	State        string        `json:"state"`
	Rules        []RuleCounter `json:"rules"`
	CounterEpoch string        `json:"counter_epoch,omitempty"`
}
type State struct {
	Snapshot  configpoc.Snapshot `json:"snapshot"`
	Effective Effective          `json:"effective"`
}
type Options struct {
	// FirewallRuleState is asserted only by a runtime with schema-4 verified
	// compilation, rollback and counter support. It is never client supplied.
	FirewallRuleState bool
	Origin            string
	Auth              *adminauth.Manager
	Backend           Backend
	Observe           func(context.Context) (Effective, error)
	Static            http.Handler
	Local             LocalBackend
	// LocalEndpointID comes from the receiving listener, never a request header.
	LocalEndpointID     string
	LocalActivationHash string
	LocalRecovery       bool
	LocalInventory      []localpolicy.Interface
}
type handler struct {
	options            Options
	host               string
	traffic            *firewalltraffic.Sampler
	preparedOperations *configpoc.ServiceV2
}

func New(options Options) (http.Handler, error) {
	origin, err := url.Parse(options.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.Path != "" || origin.User != nil || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || options.Auth == nil || (options.Backend == nil && options.Local == nil) || (options.Backend != nil && options.Observe == nil) || (options.Local != nil && options.LocalEndpointID == "") {
		return nil, errors.New("ANDEIVA_ADMIN_CONFIGURATION")
	}
	if options.Local != nil {
		if !validLocalEndpoint(options.LocalEndpointID, options.LocalActivationHash, options.LocalRecovery) {
			return nil, errors.New("ANDEIVA_ADMIN_CONFIGURATION")
		}
		inventory, err := localpolicy.Canonical(localpolicy.Config{SchemaVersion: 1, Interfaces: options.LocalInventory})
		if err != nil || len(inventory.Config.Interfaces) == 0 || len(inventory.Config.Interfaces) > 2 {
			return nil, errors.New("ANDEIVA_ADMIN_CONFIGURATION")
		}
		options.LocalInventory = inventory.Config.Interfaces
	} else if options.LocalEndpointID != "" || options.LocalActivationHash != "" || options.LocalRecovery || len(options.LocalInventory) != 0 {
		return nil, errors.New("ANDEIVA_ADMIN_CONFIGURATION")
	}
	if options.FirewallRuleState && options.Backend == nil {
		return nil, errors.New("ANDEIVA_ADMIN_CONFIGURATION")
	}
	traffic, err := firewalltraffic.New()
	if err != nil {
		return nil, err
	}
	return &handler{options: options, host: origin.Host, traffic: traffic}, nil
}
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var requestID [16]byte
	if _, err := rand.Read(requestID[:]); err != nil {
		h.fail(w, 503, "ANDEIVA_AUTH_UNAVAILABLE")
		return
	}
	w.Header().Set("X-Request-ID", hex.EncodeToString(requestID[:]))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.TLS == nil || r.Host != h.host || len(r.Header.Values("Origin")) > 1 || len(r.Header.Values("X-CSRF-Token")) > 1 || len(r.Header.Values("X-ANDEIVA-Client")) > 1 || len(r.Header.Values("Content-Type")) > 1 {
		h.deny(w, r, "unknown", "origin", http.StatusForbidden, "ANDEIVA_ORIGIN_DENIED")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != h.options.Origin {
		h.deny(w, r, "unknown", "origin", http.StatusForbidden, "ANDEIVA_ORIGIN_DENIED")
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		h.deny(w, r, "unknown", "origin", http.StatusForbidden, "ANDEIVA_ORIGIN_DENIED")
		return
	}
	if r.URL.RawPath != "" || strings.Contains(r.URL.Path, "//") {
		h.fail(w, 400, "ANDEIVA_REQUEST_INVALID")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if h.options.Static != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			h.options.Static.ServeHTTP(w, r)
			return
		}
		h.fail(w, 404, "ANDEIVA_NOT_FOUND")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !(h.preparedOperations != nil && r.URL.Path == "/api/v2/config/operations" && r.Method == http.MethodGet) && r.URL.Path != "/api/v1/firewall/history" && r.URL.Path != "/api/v1/firewall/traffic" && r.URL.Path != "/api/v1/local-services/history" && r.URL.Path != "/api/v1/effective-policies" && (r.URL.RawQuery != "" || r.URL.ForceQuery) {
		h.fail(w, 400, "ANDEIVA_REQUEST_INVALID")
		return
	}
	if r.URL.Path == "/api/v1/auth/login" {
		h.login(w, r)
		return
	}
	token, bearer, err := requestToken(r)
	if err != nil {
		h.deny(w, r, "unknown", "write", 401, "ANDEIVA_AUTH_DENIED")
		return
	}
	id, err := h.options.Auth.Authenticate(token)
	if err != nil {
		if r.Method == http.MethodPost && errors.Is(err, adminauth.ErrDenied) {
			h.deny(w, r, "unknown", "write", 401, "ANDEIVA_AUTH_DENIED")
		} else {
			h.authError(w, err)
		}
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.Method != http.MethodPost {
			h.fail(w, 405, "ANDEIVA_METHOD_NOT_ALLOWED")
			return
		}
		if r.Header.Get("Content-Type") != "application/json" || (!bearer && (!adminauth.CheckCSRF(id, r.Header.Get("X-CSRF-Token")) || r.Header.Get("Origin") != h.options.Origin)) {
			h.deny(w, r, id.Username, "csrf", 403, "ANDEIVA_CSRF_DENIED")
			return
		}
	}
	p := configpoc.Principal{ID: id.Username, Role: configpoc.Role(id.Role)}
	surface := configpoc.API
	switch r.Header.Get("X-ANDEIVA-Client") {
	case "web":
		surface = configpoc.Web
	case "cli":
		surface = configpoc.CLI
	case "", "api":
	default:
		h.fail(w, 400, "ANDEIVA_REQUEST_INVALID")
		return
	}
	// Surface is diagnostic metadata only. Every transport uses the same identity and permissions.
	if r.URL.Path == "/api/v1/system/info" {
		if r.Method != http.MethodGet {
			h.fail(w, http.StatusMethodNotAllowed, "ANDEIVA_METHOD_NOT_ALLOWED")
			return
		}
		if id.Role != "admin" && id.Role != "viewer" {
			h.deny(w, r, id.Username, "write", http.StatusForbidden, "ANDEIVA_AUTH_DENIED")
			return
		}
		h.write(w, http.StatusOK, productinfo.Current())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if h.preparedOperations != nil && strings.HasPrefix(r.URL.Path, "/api/v2/config/") {
		h.operationsV2(w, r, ctx, token)
		return
	}
	if r.URL.Path == "/api/v1/capabilities" && r.Method == http.MethodGet {
		versions := []int{}
		if h.options.Backend != nil {
			versions = append(versions, 2)
			if h.options.FirewallRuleState {
				versions = append(versions, 4)
			}
		}
		h.write(w, 200, Capabilities{FirewallConfigSchemaVersions: versions, FirewallRuleEnabled: h.options.FirewallRuleState, Firewall: h.options.Backend != nil, LocalServices: h.options.Local != nil, EndpointID: h.options.LocalEndpointID, RecoveryEndpoint: h.options.Local != nil && h.options.LocalRecovery, LocalInterfaces: h.options.LocalInventory})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/local-services") || r.URL.Path == "/api/v1/effective-policies" {
		h.local(w, r, ctx, localadmin.Context{Principal: p, Surface: surface, SessionHash: sessionHash(token), EndpointID: h.options.LocalEndpointID, ActivationHash: h.options.LocalActivationHash})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/firewall") && h.options.Backend == nil {
		h.fail(w, 404, "ANDEIVA_NOT_FOUND")
		return
	}
	switch {
	case r.URL.Path == "/api/v1/firewall/traffic" && r.Method == http.MethodGet:
		if id.Role != "admin" {
			h.deny(w, r, id.Username, "write", 403, "ANDEIVA_CONFIG_DENIED")
			return
		}
		h.trafficPage(w, r, ctx, p, surface)
	case r.URL.Path == "/api/v1/auth/session" && r.Method == http.MethodGet:
		h.write(w, 200, id)
	case r.URL.Path == "/api/v1/auth/logout" && r.Method == http.MethodPost:
		var empty struct{}
		if err := decode(w, r, &empty); err != nil {
			h.fail(w, 400, "ANDEIVA_REQUEST_INVALID")
			return
		}
		if err = h.options.Auth.Logout(token); err != nil {
			h.authError(w, err)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		h.write(w, 200, map[string]bool{"logged_out": true})
	case r.URL.Path == "/api/v1/firewall" && r.Method == http.MethodGet && r.URL.RawQuery == "":
		s, err := h.options.Backend.Execute(ctx, p, surface, configpoc.Request{Operation: configpoc.OpStatus})
		if err != nil {
			h.configError(w, err)
			return
		}
		h.write(w, 200, h.state(ctx, s))
	case r.URL.Path == "/api/v1/firewall/transactions" && r.Method == http.MethodPost && r.URL.RawQuery == "":
		if id.Role != "admin" {
			h.deny(w, r, id.Username, "write", 403, "ANDEIVA_CONFIG_DENIED")
			return
		}
		var req configpoc.Request
		if err = decode(w, r, &req); err != nil {
			h.fail(w, 400, "ANDEIVA_REQUEST_INVALID")
			return
		}
		if req.Config != nil && req.Config.SchemaVersion == 4 && !h.options.FirewallRuleState {
			h.fail(w, 400, "ANDEIVA_CONFIG_INVALID")
			return
		}
		switch req.Operation {
		case configpoc.OpStage, configpoc.OpValidate, configpoc.OpCommit, configpoc.OpConfirm, configpoc.OpSave, "rollback":
		default:
			h.fail(w, 400, "ANDEIVA_REQUEST_INVALID")
			return
		}
		s, err := h.options.Backend.Execute(ctx, p, surface, req)
		if err != nil {
			h.configError(w, err)
			return
		}
		h.write(w, 200, h.state(ctx, s))
	case r.URL.Path == "/api/v1/firewall/history" && r.Method == http.MethodGet:
		if id.Role != "admin" {
			h.deny(w, r, id.Username, "write", 403, "ANDEIVA_CONFIG_DENIED")
			return
		}
		before, limit, err := pagination(r.URL)
		if err != nil {
			h.fail(w, 400, "ANDEIVA_REQUEST_INVALID")
			return
		}
		revisions, err := h.options.Backend.History(p, before, limit)
		if err != nil {
			h.configError(w, err)
			return
		}
		audit, err := h.options.Backend.Audit(p)
		if err != nil {
			h.configError(w, err)
			return
		}
		page := []configpoc.Audit{}
		for i := len(audit) - 1; i >= 0 && len(page) < limit; i-- {
			if before == 0 || audit[i].Sequence < before {
				page = append(page, audit[i])
			}
		}
		var next uint64
		if len(revisions) == limit {
			next = revisions[len(revisions)-1].Sequence
		}
		if len(page) == limit && page[len(page)-1].Sequence > next {
			next = page[len(page)-1].Sequence
		}
		// One cursor must advance both streams without skipping the denser one.
		if next != 0 {
			for len(revisions) > 0 && revisions[len(revisions)-1].Sequence < next {
				revisions = revisions[:len(revisions)-1]
			}
			for len(page) > 0 && page[len(page)-1].Sequence < next {
				page = page[:len(page)-1]
			}
		}
		h.write(w, 200, struct {
			Revisions []configpoc.RevisionEntry `json:"revisions"`
			Audit     []configpoc.Audit         `json:"audit"`
			Next      uint64                    `json:"next_before"`
		}{revisions, page, next})
	default:
		h.fail(w, 404, "ANDEIVA_NOT_FOUND")
	}
}
func (h *handler) state(ctx context.Context, s configpoc.Snapshot) State {
	if s.Pending != nil {
		pending := *s.Pending
		pending.Lease = ""
		s.Pending = &pending
	}
	e, err := h.options.Observe(ctx)
	if err != nil {
		e = Effective{State: "unavailable", Rules: []RuleCounter{}}
		s.RecoveryRequired = true
	} else if s.RecoveryRequired || e.Revision != s.Running.Hash {
		e.State = "recovery_required"
		s.RecoveryRequired = true
	} else if s.Pending != nil {
		e.State = "pending_confirmation"
	} else {
		e.State = "verified"
	}
	if e.Rules == nil {
		e.Rules = []RuleCounter{}
	}
	return State{s, e}
}
func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		h.fail(w, 405, "ANDEIVA_METHOD_NOT_ALLOWED")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		h.fail(w, 400, "ANDEIVA_REQUEST_INVALID")
		return
	}
	client := r.Header.Get("X-ANDEIVA-Client")
	if client != "web" && client != "cli" && client != "api" {
		h.fail(w, 400, "ANDEIVA_REQUEST_INVALID")
		return
	}
	if client == "web" && r.Header.Get("Origin") != h.options.Origin {
		h.fail(w, 403, "ANDEIVA_ORIGIN_DENIED")
		return
	}
	var request struct {
		Username   string `json:"username"`
		Credential string `json:"credential"`
	}
	if err := decode(w, r, &request); err != nil {
		h.fail(w, 400, "ANDEIVA_REQUEST_INVALID")
		return
	}
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		h.authError(w, adminauth.ErrDenied)
		return
	}
	id, token, err := h.options.Auth.LoginFrom(peer.Addr(), request.Username, request.Credential)
	if err != nil {
		h.authError(w, err)
		return
	}
	if client == "web" {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: id.ExpiresAt})
		h.write(w, 200, id)
	} else {
		h.write(w, 200, struct {
			adminauth.Identity
			Token string `json:"token"`
		}{id, token})
	}
}
func requestToken(r *http.Request) (string, bool, error) {
	a := r.Header.Values("Authorization")
	cookies := r.CookiesNamed(cookieName)
	if len(a) > 1 || len(cookies) > 1 || (len(a) > 0 && len(cookies) > 0) {
		return "", false, adminauth.ErrDenied
	}
	if len(a) == 1 {
		token, ok := strings.CutPrefix(a[0], "Bearer ")
		if !ok || len(token) != 64 {
			return "", false, adminauth.ErrDenied
		}
		return token, true, nil
	}
	if len(cookies) == 1 {
		return cookies[0].Value, false, nil
	}
	return "", false, adminauth.ErrDenied
}
func decode(w http.ResponseWriter, r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if err := validateJSON(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid trailing JSON")
	}
	return nil
}
func pagination(u *url.URL) (uint64, int, error) {
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return 0, 0, err
	}
	for k, v := range q {
		if (k != "before" && k != "limit") || len(v) != 1 {
			return 0, 0, errors.New("invalid query")
		}
	}
	var before uint64
	if q.Has("before") {
		before, err = strconv.ParseUint(q.Get("before"), 10, 64)
		if err != nil {
			return 0, 0, err
		}
	}
	limit := 50
	if q.Has("limit") {
		limit, err = strconv.Atoi(q.Get("limit"))
		if err != nil || limit < 1 || limit > 100 {
			return 0, 0, errors.New("invalid limit")
		}
	}
	return before, limit, nil
}
func (h *handler) write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (h *handler) fail(w http.ResponseWriter, status int, code string) {
	h.write(w, status, map[string]string{"code": code, "request_id": w.Header().Get("X-Request-ID")})
}
func (h *handler) authError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, adminauth.ErrLimited):
		w.Header().Set("Retry-After", "1")
		h.fail(w, 429, "ANDEIVA_AUTH_RATE_LIMITED")
	case errors.Is(err, adminauth.ErrUnavailable):
		h.fail(w, 503, "ANDEIVA_AUTH_UNAVAILABLE")
	default:
		h.fail(w, 401, "ANDEIVA_AUTH_DENIED")
	}
}
func (h *handler) configError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, configpoc.ErrDenied):
		h.fail(w, 403, configpoc.ErrDenied.Error())
	case errors.Is(err, configpoc.ErrInvalid):
		h.fail(w, 400, configpoc.ErrInvalid.Error())
	case errors.Is(err, configpoc.ErrConflict):
		h.fail(w, 409, configpoc.ErrConflict.Error())
	case errors.Is(err, configpoc.ErrReplay):
		h.fail(w, 409, configpoc.ErrReplay.Error())
	case errors.Is(err, configpoc.ErrPending):
		h.fail(w, 409, configpoc.ErrPending.Error())
	case errors.Is(err, configpoc.ErrExpired):
		h.fail(w, 409, configpoc.ErrExpired.Error())
	default:
		h.fail(w, 503, "ANDEIVA_CONFIG_RECOVERY_REQUIRED")
	}
}

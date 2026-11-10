package adminapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localadmin"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

type Capabilities struct {
	FirewallConfigSchemaVersions []int                   `json:"firewall_config_schema_versions"`
	FirewallRuleEnabled          bool                    `json:"firewall_rule_enabled"`
	Firewall                     bool                    `json:"firewall"`
	LocalServices                bool                    `json:"local_services"`
	EndpointID                   string                  `json:"endpoint_id"`
	RecoveryEndpoint             bool                    `json:"recovery_endpoint"`
	LocalInterfaces              []localpolicy.Interface `json:"local_interfaces"`
}

type LocalBackend interface {
	Execute(context.Context, localadmin.Context, localadmin.Request) (configpoc.Snapshot, error)
	IssueProof(localadmin.Context, localadmin.ProofRequest) (localadmin.Proof, error)
	Status(context.Context, localadmin.Context) (localadmin.Status, error)
	Effective(context.Context, localadmin.Context, localadmin.Filter) (localadmin.Effective, error)
	History(localadmin.Context, uint64, int) ([]configpoc.RevisionEntry, error)
	Audit(localadmin.Context) ([]configpoc.Audit, error)
}

func sessionHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func validLocalEndpoint(id, activation string, recovery bool) bool {
	if recovery {
		if activation != "" || len(id) == 0 || len(id) > 64 {
			return false
		}
		for index, r := range id {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
				continue
			}
			if index > 0 && (r == '_' || r == '-' || r == '.') {
				continue
			}
			return false
		}
		return true
	}
	if !strings.HasPrefix(id, "binding-") {
		return false
	}
	for _, v := range []string{strings.TrimPrefix(id, "binding-"), activation} {
		decoded, err := hex.DecodeString(v)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != v {
			return false
		}
	}
	return true
}

func (h *handler) local(w http.ResponseWriter, r *http.Request, ctx context.Context, caller localadmin.Context) {
	backend := h.options.Local
	if backend == nil {
		h.fail(w, 404, "ANDEIVA_NOT_FOUND")
		return
	}
	read := r.Method == http.MethodGet
	if (!read || r.URL.Path == "/api/v1/local-services/history") && caller.Principal.Role != configpoc.RoleAdmin {
		h.deny(w, r, caller.Principal.ID, "write", 403, configpoc.ErrDenied.Error())
		return
	}
	switch {
	case read && r.URL.Path == "/api/v1/local-services":
		state, err := backend.Status(ctx, caller)
		if err != nil {
			h.configError(w, err)
			return
		}
		h.write(w, 200, state)
	case read && r.URL.Path == "/api/v1/effective-policies":
		filter, err := localFilter(r.URL)
		if err != nil {
			h.configError(w, err)
			return
		}
		state, err := backend.Effective(ctx, caller, filter)
		if err != nil {
			h.configError(w, err)
			return
		}
		h.write(w, 200, state)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/local-services/transactions":
		var request localadmin.Request
		if decode(w, r, &request) != nil {
			h.configError(w, configpoc.ErrInvalid)
			return
		}
		switch request.Transaction.Operation {
		case configpoc.OpStage, configpoc.OpValidate, configpoc.OpCommit, configpoc.OpConfirm, configpoc.OpSave, configpoc.OpRollback:
		default:
			h.configError(w, configpoc.ErrInvalid)
			return
		}
		if _, err := backend.Execute(ctx, caller, request); err != nil {
			h.configError(w, err)
			return
		}
		state, err := backend.Status(ctx, caller)
		if err != nil {
			h.configError(w, err)
			return
		}
		h.write(w, 200, state)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/local-services/proof":
		var request localadmin.ProofRequest
		if decode(w, r, &request) != nil {
			h.configError(w, configpoc.ErrInvalid)
			return
		}
		proof, err := backend.IssueProof(caller, request)
		if err != nil {
			h.configError(w, err)
			return
		}
		h.write(w, 200, proof)
	case read && r.URL.Path == "/api/v1/local-services/history":
		before, limit, err := pagination(r.URL)
		if err != nil {
			h.configError(w, configpoc.ErrInvalid)
			return
		}
		revisions, err := backend.History(caller, before, limit)
		if err != nil {
			h.configError(w, err)
			return
		}
		audit, err := backend.Audit(caller)
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

func localFilter(u *url.URL) (localadmin.Filter, error) {
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return localadmin.Filter{}, configpoc.ErrInvalid
	}
	for key, values := range q {
		if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 128 {
			return localadmin.Filter{}, configpoc.ErrInvalid
		}
		switch key {
		case "service", "interface", "protocol", "port", "source":
		default:
			return localadmin.Filter{}, configpoc.ErrInvalid
		}
	}
	f := localadmin.Filter{Service: q.Get("service"), Interface: q.Get("interface"), Protocol: q.Get("protocol"), Source: q.Get("source")}
	if q.Has("port") {
		port, err := strconv.ParseUint(q.Get("port"), 10, 16)
		if err != nil || port == 0 || strconv.FormatUint(port, 10) != q.Get("port") {
			return localadmin.Filter{}, configpoc.ErrInvalid
		}
		f.Port = uint16(port)
	}
	return f, nil
}

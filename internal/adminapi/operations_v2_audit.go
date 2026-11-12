package adminapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/AsterG/andeiva/internal/adminauth"
)

func (h *handler) auditV2(w http.ResponseWriter, r *http.Request, ctx context.Context, binding adminauth.SessionBinding) {
	if r.Method != http.MethodGet {
		h.fail(w, 405, "ANDEIVA_METHOD_NOT_ALLOWED")
		return
	}
	query, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil {
		h.fail(w, 400, "ANDEIVA_OPERATION_INVALID")
		return
	}
	for key, values := range query {
		if key != "before" && key != "limit" || len(values) != 1 || values[0] == "" {
			h.fail(w, 400, "ANDEIVA_OPERATION_INVALID")
			return
		}
	}
	before, limit := uint64(0), 50
	if value := query.Get("before"); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil || strconv.FormatUint(parsed, 10) != value {
			h.fail(w, 400, "ANDEIVA_OPERATION_INVALID")
			return
		}
		before = parsed
	}
	if value := query.Get("limit"); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 8)
		if err != nil || parsed < 1 || parsed > 100 || strconv.FormatUint(parsed, 10) != value {
			h.fail(w, 400, "ANDEIVA_OPERATION_INVALID")
			return
		}
		limit = int(parsed)
	}
	page, err := h.preparedOperations.AuditV2(ctx, binding, before, limit)
	if err != nil {
		h.operationErrorV2(w, err)
		return
	}
	h.writeV2(w, 200, page)
}

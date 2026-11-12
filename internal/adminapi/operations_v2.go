package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
)

const operationsV2Path = "/api/v2/config/operations"
const namespacesV2Path = "/api/v2/config/operation-namespaces"
const operationV2Limit = 1024 * 1024

// NewOperationsV2 is the explicit runtime assembly. A single v2 coordinator
// owns writes; no legacy backend is opened or consulted by this router.
func NewOperationsV2(options Options, service *configpoc.ServiceV2) (http.Handler, error) {
	if service == nil {
		return nil, configpoc.ErrInvalid
	}
	return newHandler(options, service)
}

// Only qualification tests/internal assembly can construct this prepared
// router. New and Options do not activate it or advertise v2 capabilities.
func newPreparedOperationsHandler(options Options, service *configpoc.ServiceV2) (http.Handler, error) {
	if service == nil {
		return nil, configpoc.ErrInvalid
	}
	h, err := New(options)
	if err != nil {
		return nil, err
	}
	prepared, ok := h.(*handler)
	if !ok {
		return nil, configpoc.ErrInvalid
	}
	prepared.preparedOperations = service
	return prepared, nil
}
func wireIDv2(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func decodeV2(w http.ResponseWriter, r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, operationV2Limit)
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil || !jsoncheck.UniqueControlFields(data) || !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return configpoc.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return configpoc.ErrInvalid
	}
	return nil
}
func (h *handler) writeV2(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil || len(data)+1 > operationV2Limit {
		h.fail(w, 503, "ANDEIVA_OPERATION_UNAVAILABLE")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}
func (h *handler) operationErrorV2(w http.ResponseWriter, err error) {
	code := err.Error()
	status := 503
	switch code {
	case "ANDEIVA_OPERATION_NOT_FOUND":
		status = 404
	case "ANDEIVA_OPERATION_INVALID", "ANDEIVA_CONFIG_INVALID":
		status = 400
	case "ANDEIVA_CONFIG_DENIED":
		status = 403
	case "ANDEIVA_CONFIG_CONFLICT", "ANDEIVA_OPERATION_UNCERTAIN", "ANDEIVA_CONFIG_CONFIRMATION_PENDING", "ANDEIVA_CONFIG_RECOVERY_REQUIRED":
		status = 409
	case "ANDEIVA_OPERATION_EXPIRED", "ANDEIVA_NAMESPACE_CLOSED":
		status = 410
	case "ANDEIVA_OPERATION_LIMITED":
		status = 429
	case "ANDEIVA_OPERATION_UNAVAILABLE":
	default:
		code = "ANDEIVA_OPERATION_UNAVAILABLE"
	}
	h.fail(w, status, code)
}
func operationPageQueryV2(u *url.URL) (namespace, state string, cursor uint64, limit int, err error) {
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return "", "", 0, 0, configpoc.ErrInvalid
	}
	for k, v := range q {
		if len(v) != 1 || (k != "namespace_id" && k != "state" && k != "cursor" && k != "limit") {
			return "", "", 0, 0, configpoc.ErrInvalid
		}
	}
	namespace, state = q.Get("namespace_id"), q.Get("state")
	limit = 50
	if !wireIDv2(namespace) {
		return "", "", 0, 0, configpoc.ErrInvalid
	}
	if state != "" && state != "accepted" && state != "pending" && state != "final" && state != "uncertain" {
		return "", "", 0, 0, configpoc.ErrInvalid
	}
	for _, key := range []string{"cursor", "limit"} {
		if q.Has(key) {
			n, e := strconv.ParseUint(q.Get(key), 10, 64)
			if e != nil || strconv.FormatUint(n, 10) != q.Get(key) {
				return "", "", 0, 0, configpoc.ErrInvalid
			}
			if key == "cursor" {
				cursor = n
			} else {
				if n < 1 || n > 100 {
					return "", "", 0, 0, configpoc.ErrInvalid
				}
				limit = int(n)
			}
		}
	}
	return
}
func (h *handler) operationsV2(w http.ResponseWriter, r *http.Request, ctx context.Context, token string) {
	binding, err := h.options.Auth.ResolveSession(token)
	if err != nil {
		h.fail(w, 403, "ANDEIVA_CONFIG_DENIED")
		return
	}
	service := h.preparedOperations
	path := r.URL.Path
	switch {
	case path == "/api/v2/config/current":
		if r.Method != http.MethodGet {
			h.fail(w, 405, "ANDEIVA_METHOD_NOT_ALLOWED")
			return
		}
		current, e := service.Current(binding, "")
		if e != nil {
			h.operationErrorV2(w, e)
			return
		}
		h.writeV2(w, 200, struct {
			SchemaVersion int       `json:"schema_version"`
			Current       CurrentV2 `json:"current"`
		}{2, currentDTOv2(current)})
	case path == namespacesV2Path:
		if r.Method != http.MethodPost {
			h.fail(w, 405, "ANDEIVA_METHOD_NOT_ALLOWED")
			return
		}
		var body struct {
			Domain string `json:"domain"`
		}
		if decodeV2(w, r, &body) != nil || (body.Domain != "firewall" && body.Domain != "routed") {
			h.fail(w, 400, "ANDEIVA_OPERATION_INVALID")
			return
		}
		ns, e := service.Namespace(binding, body.Domain, time.Hour)
		if e != nil {
			h.operationErrorV2(w, e)
			return
		}
		h.writeV2(w, 201, NamespaceResponseV2{SchemaVersion: 2, Namespace: ns.ID, State: "open", AdmitUntil: ns.AdmitUntil})
	case path == operationsV2Path+"/admit":
		if r.Method != http.MethodPost {
			h.fail(w, 405, "ANDEIVA_METHOD_NOT_ALLOWED")
			return
		}
		var body AdmitRequestV2
		if decodeV2(w, r, &body) != nil || !wireIDv2(body.Namespace) || body.Expected == 0 {
			h.fail(w, 400, "ANDEIVA_OPERATION_INVALID")
			return
		}
		result, e := service.AdmitObserved(binding, body.Namespace, uint64(body.Expected), body.Request.canonical())
		if e != nil {
			h.operationErrorV2(w, e)
			return
		}
		h.writeV2(w, 201, OperationResponseV2{SchemaVersion: 2, Operation: operationDTOv2(result.Operation), Current: currentDTOv2(result.Current)})
	case path == operationsV2Path:
		if r.Method != http.MethodGet {
			h.fail(w, 405, "ANDEIVA_METHOD_NOT_ALLOWED")
			return
		}
		ns, state, cursor, limit, e := operationPageQueryV2(r.URL)
		if e != nil {
			h.fail(w, 400, "ANDEIVA_OPERATION_INVALID")
			return
		}
		page, e := service.ObserveList(binding, ns, state, cursor, limit)
		if e != nil {
			h.operationErrorV2(w, e)
			return
		}
		result := OperationPageV2{SchemaVersion: 2, Operations: []OperationV2{}, NextCursor: DecimalV2(page.Cursor), Current: currentDTOv2(page.Current)}
		for _, op := range page.Operations {
			result.Operations = append(result.Operations, operationDTOv2(op))
		}
		h.writeV2(w, 200, result)
	case strings.HasPrefix(path, operationsV2Path+"/"):
		id := strings.TrimPrefix(path, operationsV2Path+"/")
		execute := strings.HasSuffix(id, "/execute")
		if execute {
			id = strings.TrimSuffix(id, "/execute")
		}
		if !wireIDv2(id) {
			h.fail(w, 404, "ANDEIVA_OPERATION_NOT_FOUND")
			return
		}
		var result configpoc.ObservationV2
		if execute {
			if r.Method != http.MethodPost {
				h.fail(w, 405, "ANDEIVA_METHOD_NOT_ALLOWED")
				return
			}
			if decodeV2(w, r, &struct{}{}) != nil {
				h.fail(w, 400, "ANDEIVA_OPERATION_INVALID")
				return
			}
			result, err = service.ExecuteObserved(ctx, binding, id)
		} else {
			if r.Method != http.MethodGet {
				h.fail(w, 405, "ANDEIVA_METHOD_NOT_ALLOWED")
				return
			}
			result, err = service.Observe(binding, id)
		}
		if err != nil {
			h.operationErrorV2(w, err)
			return
		}
		if execute && result.Operation.State == "uncertain" {
			h.fail(w, 409, "ANDEIVA_OPERATION_UNCERTAIN")
			return
		}
		status := 200
		if result.Operation.State == "pending" {
			status = 202
		}
		h.writeV2(w, status, OperationResponseV2{SchemaVersion: 2, Operation: operationDTOv2(result.Operation), Current: currentDTOv2(result.Current)})
	case strings.HasPrefix(path, namespacesV2Path+"/") && strings.HasSuffix(path, "/close"):
		if r.Method != http.MethodPost {
			h.fail(w, 405, "ANDEIVA_METHOD_NOT_ALLOWED")
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(path, namespacesV2Path+"/"), "/close")
		if !wireIDv2(id) {
			h.fail(w, 404, "ANDEIVA_OPERATION_NOT_FOUND")
			return
		}
		if decodeV2(w, r, &struct{}{}) != nil {
			h.fail(w, 400, "ANDEIVA_OPERATION_INVALID")
			return
		}
		if err := service.CloseObservedNamespace(binding, id); err != nil {
			h.operationErrorV2(w, err)
			return
		}
		h.writeV2(w, 200, NamespaceClosedV2{SchemaVersion: 2, Namespace: id, State: "closed"})
	default:
		h.fail(w, 404, "ANDEIVA_NOT_FOUND")
	}
}

package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
)

const operationsPathV2 = "/api/v2/config/operations"
const namespacesPathV2 = "/api/v2/config/operation-namespaces"

func clientIDv2(id string) bool {
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
func (c *Client) callV2(ctx context.Context, method, path string, body, out any, statuses ...int) error {
	if c.token == "" {
		return ErrCredentials
	}
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil || len(data) > 1024*1024 {
			return ErrConfiguration
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(data))
	if err != nil {
		return ErrConfiguration
	}
	req.Header.Set("X-ANDEIVA-Client", "cli")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return ErrTransport
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 || response.Header.Get("Content-Type") != "application/json" || !jsoncheck.UniqueControlFields(data) {
		return ErrResponse
	}
	ok := false
	for _, status := range statuses {
		ok = ok || response.StatusCode == status
	}
	if !ok {
		var result APIError
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || !safeCode(result.Code) || !safeID(result.RequestID) {
			return ErrResponse
		}
		return &result
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrResponse
	}
	return nil
}
func clientHashV2(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}

func validCurrentV2(current adminapi.CurrentV2) bool {
	if !clientIDv2(current.Global.Lineage) || current.Global.Generation == 0 {
		return false
	}
	for _, hash := range []string{current.Global.Running, current.Global.Startup} {
		if !clientHashV2(hash) {
			return false
		}
	}
	if current.Domain == "firewall" {
		return current.Routed == nil && current.DomainGenerations == nil && validSnapshotV2(current.Snapshot, false, false)
	}
	if current.Domain != "routed" || current.Routed == nil || current.DomainGenerations == nil || current.Routed.SchemaVersion != 7 || !validSnapshotV2(current.Snapshot, true, false) || !validSnapshotV2(current.Routed.LocalServices, false, true) {
		return false
	}
	routed, generations := current.Routed, current.DomainGenerations
	if generations.Firewall != current.Snapshot.Generation || generations.Network != generations.Firewall || generations.LocalServices != routed.LocalServices.Generation || current.Global.Running != routed.Running.Hash || current.Global.Startup != routed.Startup.Hash {
		return false
	}
	for _, pair := range []struct {
		firewall, local configpoc.Revision
		composite       configpoc.CompositeRevisionV1
	}{
		{current.Snapshot.Running, routed.LocalServices.Running, routed.Running},
		{current.Snapshot.Startup, routed.LocalServices.Startup, routed.Startup},
		{current.Snapshot.LastGood, routed.LocalServices.LastGood, routed.LastGood},
	} {
		bundle, err := configpoc.NewRoutedActivationBundleV1(pair.firewall, pair.local)
		if err != nil || !reflect.DeepEqual(bundle.Composite, pair.composite) {
			return false
		}
	}
	if routed.Candidate == nil {
		return routed.CandidateGroup == nil && current.Snapshot.Candidate == nil && routed.LocalServices.Candidate == nil
	}
	firewall, local, group := current.Snapshot.Candidate, routed.LocalServices.Candidate, routed.CandidateGroup
	if firewall == nil || local == nil || group == nil || (firewall.Revision.Config.SchemaVersion != 4 && firewall.Revision.Config.SchemaVersion != 6) || !clientIDv2(group.Operation) || group.Owner != firewall.Owner || group.Owner != local.Owner || !clientHashV2(group.Base) || len(group.Domains) != 2 || group.Domains[0] != "firewall" || group.Domains[1] != "local_services" {
		return false
	}
	bundle, err := configpoc.NewRoutedActivationBundleV1(firewall.Revision, local.Revision)
	return err == nil && reflect.DeepEqual(bundle.Composite, *routed.Candidate)
}

func validSnapshotV2(snapshot adminapi.SnapshotV2, routed, local bool) bool {
	if snapshot.Generation == 0 {
		return false
	}
	validRevision := func(revision configpoc.Revision) bool {
		if local {
			if revision.Config.SchemaVersion != 3 || len(revision.Config.Rules) != 0 {
				return false
			}
		} else if revision.Config.SchemaVersion != 4 && !(routed && revision.Config.SchemaVersion == 6) {
			return false
		}
		var canonical configpoc.Revision
		var err error
		if revision.Config.SchemaVersion == 6 {
			canonical, err = configpoc.CanonicalRouted(revision.Config)
		} else {
			canonical, err = configpoc.Canonical(revision.Config)
		}
		return err == nil && canonical.Hash == revision.Hash
	}
	for _, revision := range []configpoc.Revision{snapshot.Running, snapshot.Startup, snapshot.LastGood} {
		if !validRevision(revision) {
			return false
		}
	}
	if candidate := snapshot.Candidate; candidate != nil {
		if !validRevision(candidate.Revision) || !clientHashV2(candidate.Base) || !clientIDv2(candidate.Owner) {
			return false
		}
	}
	if pending := snapshot.Pending; pending != nil {
		if !validRevision(pending.Previous) || !clientIDv2(pending.Owner) || !clientIDv2(pending.Lease) || pending.Deadline.IsZero() {
			return false
		}
	}
	if len(snapshot.Revoked) > 256 {
		return false
	}
	seen := map[string]bool{}
	for _, subject := range snapshot.Revoked {
		if !clientIDv2(subject) || seen[subject] {
			return false
		}
		seen[subject] = true
	}
	return true
}
func validOperationV2(op adminapi.OperationV2) bool {
	if !clientIDv2(op.ID) || !clientIDv2(op.Namespace) || (op.Domain != "firewall" && op.Domain != "routed") || op.Expected == 0 || len(op.Fingerprint) != 64 || strings.Trim(op.Fingerprint, "0123456789abcdef") != "" || op.Accepted.IsZero() || !op.ExecuteBefore.After(op.Accepted) {
		return false
	}
	if op.State != "accepted" && op.State != "pending" && op.State != "final" && op.State != "uncertain" {
		return false
	}
	switch op.Kind {
	case configpoc.OpReplaceCandidate, configpoc.OpDiscardCandidate:
		if op.Domain != "routed" {
			return false
		}
	case configpoc.OpStage, configpoc.OpValidate, configpoc.OpCommit, configpoc.OpConfirm, configpoc.OpSave, configpoc.OpRollback, configpoc.OpRecover, configpoc.OpRevoke:
	default:
		return false
	}
	if op.State == "final" && (op.Outcome == nil || op.Completed == nil || op.RetainUntil == nil) {
		return false
	}
	if op.Outcome != nil {
		switch op.Outcome.Code {
		case "applied", "applied_pending_confirmation", "rejected", "failed_rolled_back", "expired_without_effects":
		case "profile_changed_without_effects":
			if op.State != "final" || op.Outcome.ErrorCode != "ANDEIVA_RESERVE_PROFILE_CHANGED" {
				return false
			}
		case "confirmation_resolved_without_effects":
			if op.State != "final" || op.Outcome.ErrorCode != "ANDEIVA_CONFIRMATION_RESOLVED" {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func (c *Client) NamespaceV2(ctx context.Context, domain string) (adminapi.NamespaceResponseV2, error) {
	var result adminapi.NamespaceResponseV2
	if domain != "firewall" && domain != "routed" {
		return result, ErrConfiguration
	}
	err := c.callV2(ctx, http.MethodPost, namespacesPathV2, struct {
		Domain string `json:"domain"`
	}{domain}, &result, 201)
	if err == nil && (result.SchemaVersion != 2 || !clientIDv2(result.Namespace) || result.State != "open" || result.AdmitUntil.IsZero()) {
		err = ErrResponse
	}
	return result, err
}
func (c *Client) AdmitV2(ctx context.Context, request adminapi.AdmitRequestV2) (adminapi.OperationResponseV2, error) {
	var result adminapi.OperationResponseV2
	if !clientIDv2(request.Namespace) || request.Expected == 0 {
		return result, ErrConfiguration
	}
	err := c.callV2(ctx, http.MethodPost, operationsPathV2+"/admit", request, &result, 201)
	if err == nil && (!validOperationV2(result.Operation) || !validCurrentV2(result.Current) || result.SchemaVersion != 2 || result.Operation.Namespace != request.Namespace || result.Operation.Expected != request.Expected || result.Operation.Kind != request.Request.Operation || result.Operation.State != "accepted" || result.Operation.Outcome != nil || result.Operation.Completed != nil || result.Operation.RetainUntil != nil || result.Operation.Target != request.Request.Target || result.Operation.Origin != request.Request.Origin) {
		err = ErrResponse
	}
	return result, err
}
func (c *Client) operationV2(ctx context.Context, id string, execute bool) (adminapi.OperationResponseV2, error) {
	var result adminapi.OperationResponseV2
	if !clientIDv2(id) {
		return result, ErrConfiguration
	}
	method, path, body := http.MethodGet, operationsPathV2+"/"+id, any(nil)
	if execute {
		method, path, body = http.MethodPost, path+"/execute", struct{}{}
	}
	err := c.callV2(ctx, method, path, body, &result, 200, 202)
	if err == nil && (result.SchemaVersion != 2 || result.Operation.ID != id || !validOperationV2(result.Operation) || !validCurrentV2(result.Current)) {
		err = ErrResponse
	}
	return result, err
}
func (c *Client) ExecuteV2(ctx context.Context, id string) (adminapi.OperationResponseV2, error) {
	return c.operationV2(ctx, id, true)
}
func (c *Client) OperationV2(ctx context.Context, id string) (adminapi.OperationResponseV2, error) {
	return c.operationV2(ctx, id, false)
}
func (c *Client) OperationsV2(ctx context.Context, namespace, state string, cursor uint64, limit int) (adminapi.OperationPageV2, error) {
	var result adminapi.OperationPageV2
	if !clientIDv2(namespace) || limit < 1 || limit > 100 || (state != "" && state != "accepted" && state != "pending" && state != "final" && state != "uncertain") {
		return result, ErrConfiguration
	}
	query := url.Values{"namespace_id": {namespace}, "cursor": {strconv.FormatUint(cursor, 10)}, "limit": {strconv.Itoa(limit)}}
	if state != "" {
		query.Set("state", state)
	}
	err := c.callV2(ctx, http.MethodGet, operationsPathV2+"?"+query.Encode(), nil, &result, 200)
	if err == nil {
		if result.SchemaVersion != 2 || !validCurrentV2(result.Current) || result.Operations == nil || len(result.Operations) > limit || uint64(result.NextCursor) < cursor {
			err = ErrResponse
		}
		for _, op := range result.Operations {
			if !validOperationV2(op) || op.Namespace != namespace || (state != "" && op.State != state) {
				err = ErrResponse
			}
		}
	}
	return result, err
}
func (c *Client) CloseNamespaceV2(ctx context.Context, id string) (adminapi.NamespaceClosedV2, error) {
	var result adminapi.NamespaceClosedV2
	if !clientIDv2(id) {
		return result, ErrConfiguration
	}
	err := c.callV2(ctx, http.MethodPost, namespacesPathV2+"/"+id+"/close", struct{}{}, &result, 200)
	if err == nil && (result.SchemaVersion != 2 || result.Namespace != id || result.State != "closed") {
		err = ErrResponse
	}
	return result, err
}

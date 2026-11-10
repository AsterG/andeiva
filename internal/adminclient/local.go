package adminclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/localadmin"
)

func (c *Client) Capabilities(ctx context.Context) (adminapi.Capabilities, error) {
	var out adminapi.Capabilities
	err := c.call(ctx, http.MethodGet, "/api/v1/capabilities", nil, &out)
	return out, err
}
func (c *Client) LocalState(ctx context.Context) (localadmin.Status, error) {
	var out localadmin.Status
	err := c.call(ctx, http.MethodGet, "/api/v1/local-services", nil, &out)
	return out, err
}
func (c *Client) LocalExecute(ctx context.Context, request localadmin.Request) (localadmin.Status, error) {
	var out localadmin.Status
	err := c.call(ctx, http.MethodPost, "/api/v1/local-services/transactions", request, &out)
	return out, err
}
func (c *Client) LocalProof(ctx context.Context, request localadmin.ProofRequest) (localadmin.Proof, error) {
	var out localadmin.Proof
	err := c.call(ctx, http.MethodPost, "/api/v1/local-services/proof", request, &out)
	return out, err
}
func (c *Client) LocalHistory(ctx context.Context, before uint64, limit int) (History, error) {
	if limit < 1 || limit > 100 {
		return History{}, ErrConfiguration
	}
	q := url.Values{"before": {jsonNumber(before)}, "limit": {strconv.Itoa(limit)}}
	var out History
	err := c.call(ctx, http.MethodGet, "/api/v1/local-services/history?"+q.Encode(), nil, &out)
	return out, err
}
func (c *Client) EffectivePolicies(ctx context.Context, f localadmin.Filter) (localadmin.Effective, error) {
	q := url.Values{}
	for key, value := range map[string]string{"service": f.Service, "interface": f.Interface, "protocol": f.Protocol, "source": f.Source} {
		if value != "" {
			q.Set(key, value)
		}
	}
	if f.Port != 0 {
		q.Set("port", strconv.Itoa(int(f.Port)))
	}
	path := "/api/v1/effective-policies"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out localadmin.Effective
	err := c.call(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

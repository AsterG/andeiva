package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/AsterG/andeiva/internal/productinfo"
)

// SystemInfo reads the running server's product identity, independently of this
// client's build. It never consults configuration revisions or local inventory.
func (c *Client) SystemInfo(ctx context.Context) (productinfo.Info, error) {
	if c.token == "" {
		return productinfo.Info{}, ErrConfiguration
	}
	var raw json.RawMessage
	if err := c.callWithLimit(ctx, http.MethodGet, "/api/v1/system/info", nil, &raw, 4096); err != nil {
		return productinfo.Info{}, err
	}
	return decodeSystemInfo(raw)
}

func decodeSystemInfo(data []byte) (productinfo.Info, error) {
	var info productinfo.Info
	d := json.NewDecoder(bytes.NewReader(data))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return info, ErrResponse
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return productinfo.Info{}, ErrResponse
		}
		seen[name] = true
		value, err := d.Token()
		text, ok := value.(string)
		if err != nil || !ok {
			return productinfo.Info{}, ErrResponse
		}
		switch name {
		case "product":
			info.Product = text
		case "version":
			info.Version = text
		case "channel":
			info.Channel = text
		case "update_status":
			info.UpdateStatus = text
		default:
			return productinfo.Info{}, ErrResponse
		}
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') || d.Decode(new(any)) != io.EOF || (seen["version"] && info.Version == "") || !productinfo.Valid(info) {
		return productinfo.Info{}, ErrResponse
	}
	return info, nil
}

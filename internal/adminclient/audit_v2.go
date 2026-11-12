package adminclient

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func (c *Client) ConfigurationAuditV2(ctx context.Context, before uint64, limit int) (configpoc.AuditPageV2, error) {
	var page configpoc.AuditPageV2
	if limit < 1 || limit > 100 {
		return page, ErrConfiguration
	}
	path := "/api/v2/config/audit?before=" + strconv.FormatUint(before, 10) + "&limit=" + strconv.Itoa(limit)
	if err := c.callV2(ctx, http.MethodGet, path, nil, &page, 200); err != nil {
		return page, err
	}
	if page.SchemaVersion != 1 || page.Events == nil || len(page.Events) > limit {
		return configpoc.AuditPageV2{}, ErrResponse
	}
	previous := before
	for _, event := range page.Events {
		if event.Sequence == 0 || previous != 0 && event.Sequence >= previous || event.Generation == 0 || event.At.IsZero() || !clientIDv2(event.ActorID) || !clientIDv2(event.OperationID) || !clientIDv2(event.Operation) || !clientIDv2(event.Result) || !clientHashV2(event.Running) || !clientHashV2(event.Startup) || len(event.ActorName) > 128 || !utf8.ValidString(event.ActorName) || strings.IndexFunc(event.ActorName, unicode.IsControl) >= 0 {
			return configpoc.AuditPageV2{}, ErrResponse
		}
		previous = event.Sequence
	}
	if page.NextBefore != 0 && (len(page.Events) == 0 || page.NextBefore != previous) {
		return configpoc.AuditPageV2{}, ErrResponse
	}
	return page, nil
}

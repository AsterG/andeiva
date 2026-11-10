package adminapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalltraffic"
)

func trafficPagination(u *url.URL) (uint64, int, string, error) {
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return 0, 0, "", firewalltraffic.ErrInvalid
	}
	stream := ""
	if values, ok := query["stream"]; ok {
		if len(values) != 1 {
			return 0, 0, "", firewalltraffic.ErrInvalid
		}
		stream = values[0]
		raw, err := hex.DecodeString(stream)
		if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != stream {
			return 0, 0, "", firewalltraffic.ErrInvalid
		}
		query.Del("stream")
	}
	remaining := *u
	remaining.RawQuery = query.Encode()
	before, limit, err := pagination(&remaining)
	if err != nil || (before > 0 && stream == "") || (before == 0 && stream != "") {
		return 0, 0, "", firewalltraffic.ErrInvalid
	}
	return before, limit, stream, nil
}
func (h *handler) trafficPage(w http.ResponseWriter, r *http.Request, ctx context.Context, p configpoc.Principal, surface configpoc.Surface) {
	before, limit, stream, err := trafficPagination(r.URL)
	if err != nil {
		h.fail(w, 400, "ANDEIVA_REQUEST_INVALID")
		return
	}
	page, err := h.traffic.Read(ctx, before, limit, stream, func(ctx context.Context) (firewalltraffic.Observation, error) {
		initial, err := h.options.Backend.Execute(ctx, p, surface, configpoc.Request{Operation: configpoc.OpStatus})
		if err != nil || initial.RecoveryRequired {
			return firewalltraffic.Observation{}, firewalltraffic.ErrUnavailable
		}
		observed, err := h.options.Observe(ctx)
		if err != nil || observed.Revision != initial.Running.Hash {
			return firewalltraffic.Observation{}, firewalltraffic.ErrUnavailable
		}
		final, err := h.options.Backend.Execute(ctx, p, surface, configpoc.Request{Operation: configpoc.OpStatus})
		if err != nil || final.RecoveryRequired || final.Generation != initial.Generation || final.Running.Hash != observed.Revision {
			return firewalltraffic.Observation{}, firewalltraffic.ErrUnavailable
		}
		return firewalltraffic.Observation{Revision: final.Running, CounterEpoch: observed.CounterEpoch, Counters: observed.Rules}, nil
	})
	if err != nil {
		if errors.Is(err, firewalltraffic.ErrStreamChanged) {
			h.fail(w, 409, firewalltraffic.ErrStreamChanged.Error())
		} else {
			h.fail(w, 503, firewalltraffic.ErrUnavailable.Error())
		}
		return
	}
	h.write(w, 200, page)
}

//go:build linux

package localruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestResetCauseRetainsFirstAllowedEvent(t *testing.T) {
	i := &instance{}
	i.noteFailure("api", "credential-must-not-be-recorded")
	if i.resetCause().Reason != "" {
		t.Fatal("unbounded reason accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan childEvent, 1)
	readEvents(ctx, "api", "instance", strings.NewReader("{\"event\":\"failure\",\"reason\":\"observation_unavailable\"}\n"), out, nil, cancel, i.noteFailure)
	i.noteFailure("api", "process_exit")
	cause := i.resetCause()
	if cause.Role != "api" || cause.Reason != "observation_unavailable" || cause.At.IsZero() {
		t.Fatal("first diagnostic lost")
	}
	if (<-out).event.Reason != cause.Reason {
		t.Fatal("failure not forwarded")
	}
}

func TestInvalidChildReasonIsNotLogged(t *testing.T) {
	i := &instance{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan childEvent, 1)
	readEvents(ctx, "api", "instance", strings.NewReader("{\"event\":\"failure\",\"reason\":\"private-credential\"}\n"), out, nil, cancel, i.noteFailure)
	if i.resetCause().Reason != "invalid_event" || ctx.Err() == nil || len(out) != 0 {
		t.Fatal("invalid diagnostic escaped")
	}
	var b bytes.Buffer
	l := &eventsLog{out: &b}
	if err := l.write(map[string]any{"event": "reset_requested", "reason": i.resetCause().Reason}); err != nil {
		t.Fatal(err)
	}
	var record struct {
		At     time.Time `json:"at"`
		Reason string    `json:"reason"`
	}
	if json.Unmarshal(b.Bytes(), &record) != nil || record.At.IsZero() || record.Reason != "invalid_event" || strings.Contains(b.String(), "private-credential") {
		t.Fatal("unsafe event log")
	}
}

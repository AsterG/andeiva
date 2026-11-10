package firewallipc

import (
	"context"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/localpolicy"
)

func TestLocalObservationRejectsMixedAndIncompleteDomains(t *testing.T) {
	for _, scenario := range []string{"valid", "forwarding", "missing", "invalid_hash", "too_many", "unexpected_local", "legacy"} {
		t.Run(scenario, func(t *testing.T) {
			c := pair(t, func(m Message) Reply {
				r := bound(m)
				r.CounterEpoch = ""
				r.Hash = strings.Repeat("a", 64)
				r.Local = &localpolicy.Observation{Revision: strings.Repeat("b", 64)}
				switch scenario {
				case "forwarding":
					r.Counters = []Counter{{ID: "foreign"}}
				case "missing":
					r.Local = nil
				case "invalid_hash":
					r.Local.Revision = "invalid"
				case "too_many":
					r.Local.Listeners = make([]localpolicy.Listener, 9)
				}
				return r
			})
			c.local = scenario != "legacy"
			verb := "observe"
			if scenario == "unexpected_local" {
				verb = "state"
			}
			_, err := c.Call(context.Background(), Message{Verb: verb})
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("unexpected result: %v", err)
			}
			if scenario != "valid" && !c.dead {
				t.Fatal("invalid domain did not poison channel")
			}
		})
	}
}

func TestLocalReplyBoundDoesNotExpandRequests(t *testing.T) {
	data := []byte(`{"padding":"` + strings.Repeat("a", MaxFrame) + `"}`)
	var out map[string]string
	if Decode(data, &out) == nil {
		t.Fatal("request bound expanded")
	}
	if decodeBounded(data, &out, LocalReplyMaxFrame) != nil {
		t.Fatal("bounded large reply rejected")
	}
	if decodeBounded([]byte(`{"x":1,"X":2}`), new(map[string]int), LocalReplyMaxFrame) == nil {
		t.Fatal("duplicate reply keys accepted")
	}
}

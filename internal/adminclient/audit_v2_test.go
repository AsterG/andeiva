package adminclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestConfigurationAuditV2BoundsAndExactSequence(t *testing.T) {
	for _, mode := range []string{"valid", "ascending", "wrong-cursor", "nil-events", "control-name"} {
		t.Run(mode, func(t *testing.T) {
			event := configpoc.AuditEventV2{Sequence: ^uint64(0), At: time.Now().UTC(), ActorID: "subject-a", ActorName: "alice", OperationID: "operation-a", Operation: "save", Result: "applied", Generation: ^uint64(0), Running: strings.Repeat("a", 64), Startup: strings.Repeat("b", 64)}
			page := configpoc.AuditPageV2{SchemaVersion: 1, Events: []configpoc.AuditEventV2{event}}
			switch mode {
			case "ascending":
				page.Events = append(page.Events, event)
			case "wrong-cursor":
				page.NextBefore = 1
			case "nil-events":
				page.Events = nil
			case "control-name":
				page.Events[0].ActorName = "alice\x1b[2J"
			}
			client, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/api/v2/config/audit" || r.URL.RawQuery != "before=0&limit=50" {
					t.Error("unexpected audit request", r.URL.String())
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(page)
			}))
			client.token = strings.Repeat("a", 64)
			got, err := client.ConfigurationAuditV2(context.Background(), 0, 50)
			if mode == "valid" {
				if err != nil || got.Events[0].Sequence != ^uint64(0) {
					t.Fatal("exact sequence lost", err)
				}
			} else if !errors.Is(err, ErrResponse) {
				t.Fatal("invalid audit accepted", mode, err)
			}
		})
	}
}

//go:build linux

package adminapi

import (
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestRuntimeAuditV2TLSBoundariesAndRBAC(t *testing.T) {
	f := runtimeOperationsFixtureV2(t)
	var page configpoc.AuditPageV2
	f.call(t, "GET", "/api/v2/config/audit?limit=1", nil, 200, &page)
	if page.SchemaVersion != 1 || len(page.Events) != 1 || page.Events[0].ActorID != "system" {
		t.Fatal("selected initialization audit missing", page)
	}
	for _, query := range []string{"limit=0", "limit=101", "limit=01", "limit=1&limit=2", "before=-1", "before=18446744073709551616", "before=01", "path=../../etc", "limit=1;ignored=2", "limit=%zz"} {
		f.call(t, "GET", "/api/v2/config/audit?"+query, nil, 400, nil)
	}
	f.call(t, "POST", "/api/v2/config/audit", struct{}{}, 405, nil)
	for _, name := range []string{"", "viewer"} {
		headers := map[string]string{"X-ANDEIVA-Client": "cli"}
		want := 401
		if name != "" {
			headers["Authorization"] = "Bearer " + f.tokens[name]
			want = 403
		}
		status, body, _ := f.api.request(t, "GET", "/api/v2/config/audit", "", headers)
		if status != want || strings.Contains(body, "actor_id") || strings.Contains(body, "running_revision") {
			t.Fatal("audit disclosure", name, status, body)
		}
	}
}

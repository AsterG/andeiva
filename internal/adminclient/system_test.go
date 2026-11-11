package adminclient

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestSystemInfoRequiresSession(t *testing.T) {
	calls := 0
	c, _ := trustedClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	if _, err := c.SystemInfo(context.Background()); !errors.Is(err, ErrConfiguration) || calls != 0 {
		t.Fatal("anonymous metadata request reached the network")
	}
}

func TestSystemInfoBoundedPublicContract(t *testing.T) {
	const valid = `{"product":"ANDEIVA Security Gateway","version":"0.1.0~alpha15","channel":"experimental","update_status":"unavailable"}`
	for _, tc := range []struct {
		name, data string
		valid      bool
	}{
		{"preview", valid, true},
		{"development", `{"product":"ANDEIVA Security Gateway","channel":"development","update_status":"unavailable"}`, true},
		{"unknown-field", strings.TrimSuffix(valid, "}") + `,"os_version":"private"}`, false},
		{"case-folded-field", strings.Replace(valid, `"product"`, `"Product"`, 1), false},
		{"duplicate-field", strings.TrimSuffix(valid, "}") + `,"version":"0.1.0~alpha15"}`, false},
		{"null", "null", false}, {"array", "[]", false},
		{"null-field", strings.Replace(valid, `"0.1.0~alpha15"`, "null", 1), false},
		{"missing-field", `{"product":"ANDEIVA Security Gateway","channel":"development"}`, false},
		{"invalid-version", strings.Replace(valid, "0.1.0~alpha15", "go1.27.4", 1), false},
		{"wrong-channel", strings.Replace(valid, "experimental", "stable", 1), false},
		{"false-update", strings.Replace(valid, "unavailable", "up-to-date", 1), false},
		{"trailing-json", valid + "{}", false},
		{"oversized", valid + strings.Repeat(" ", 4096), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/system/info" || r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) || r.Header.Get("X-ANDEIVA-Client") != "cli" {
					t.Error("metadata contract changed")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.data))
			}))
			c.token = strings.Repeat("a", 64)
			info, err := c.SystemInfo(context.Background())
			if tc.valid {
				if err != nil || info.Product != "ANDEIVA Security Gateway" || info.UpdateStatus != "unavailable" {
					t.Fatalf("valid metadata rejected: %v", err)
				}
			} else if !errors.Is(err, ErrResponse) || info.Product != "" {
				t.Fatalf("unverified metadata returned: %v", err)
			}
		})
	}
}

func BenchmarkDecodeSystemInfo(b *testing.B) {
	data := []byte(`{"product":"ANDEIVA Security Gateway","version":"0.1.0~alpha15","channel":"experimental","update_status":"unavailable"}`)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := decodeSystemInfo(data); err != nil {
			b.Fatal(err)
		}
	}
}

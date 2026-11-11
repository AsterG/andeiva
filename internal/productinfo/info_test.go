package productinfo

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProductIdentityValidation(t *testing.T) {
	maxDigits := 64 - len("0.1.0~alpha")
	for _, version := range []string{"0.1.0~alpha1", "0.1.0~alpha15", "0.1.0~alpha" + strings.Repeat("9", maxDigits)} {
		info := fromVersion(version)
		if info.Product != "ANDEIVA Security Gateway" || info.Version != version || info.Channel != "experimental" || info.UpdateStatus != "unavailable" || !Valid(info) {
			t.Fatal("valid preview identity rejected")
		}
	}
	for _, version := range []string{"", "development", "0.1.0", "0.1.0~alpha0", "0.1.0~alpha01", "0.1.0~alpha1\n", "0.1.0~alpha1\x00", "/private/build", "go1.27.4", "0.1.0~alpha" + strings.Repeat("9", maxDigits+1)} {
		info := fromVersion(version)
		if info.Version != "" || info.Channel != "development" || info.UpdateStatus != "unavailable" || !Valid(info) {
			t.Fatal("invalid build metadata did not fall back safely")
		}
		data, err := json.Marshal(info)
		if err != nil || strings.Contains(string(data), `"version"`) {
			t.Fatal("unavailable version was fabricated")
		}
	}
	for _, bad := range []Info{{}, {Product: "other", Channel: "development", UpdateStatus: "unavailable"}, {Product: "ANDEIVA Security Gateway", Version: "private", Channel: "development", UpdateStatus: "unavailable"}, {Product: "ANDEIVA Security Gateway", Channel: "development", UpdateStatus: "up-to-date"}, {Product: "ANDEIVA Security Gateway", Version: "0.1.0~alpha15", Channel: "development", UpdateStatus: "unavailable"}} {
		if Valid(bad) {
			t.Fatal("unsafe public identity accepted")
		}
	}
}

func TestProductIdentityIgnoresRuntimeEnvironment(t *testing.T) {
	previous := Version
	Version = ""
	t.Cleanup(func() { Version = previous })
	t.Setenv("ANDEIVA_VERSION", "0.1.0~alpha999")
	t.Setenv("VERSION", "0.1.0~alpha999")
	if info := Current(); info.Version != "" || info.Channel != "development" || info.UpdateStatus != "unavailable" {
		t.Fatal("runtime environment changed product identity")
	}
}

func BenchmarkProductIdentity(b *testing.B) {
	for _, version := range []string{"", "0.1.0~alpha15"} {
		name := "development"
		if version != "" {
			name = "experimental"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = fromVersion(version)
			}
		})
	}
}

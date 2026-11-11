package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/productinfo"
)

func TestSystemInfoLocalizedHelpAndPrefixes(t *testing.T) {
	for _, locale := range []string{"en", "es", "pt"} {
		for _, command := range []string{"sy", "sys", "syst", "syste", "system"} {
			var out, errOut bytes.Buffer
			if code := Run([]string{"--lang", locale, command, "h"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "--credentials-file") || !strings.Contains(out.String(), "--version") || errOut.Len() != 0 {
				t.Fatalf("localized system help failed: %s %s", locale, command)
			}
		}
	}
	for _, args := range [][]string{{"s", "info"}, {"system", "unknown"}, {"system", "info"}, {"system", "info", "--insecure"}, {"system", "info", "--url", "first", "--url", "second"}, {"system", "info", "--credential", "private-value"}, {"--version", "extra"}} {
		var out, errOut bytes.Buffer
		if code := Run(args, &out, &errOut); code != 2 || out.Len() != 0 || strings.Contains(errOut.String(), "private-value") {
			t.Fatal("unsafe/ambiguous system arguments accepted")
		}
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"firewall", "completion"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "system)") || !strings.Contains(out.String(), "--version") {
		t.Fatal("system completion missing")
	}
}

func TestLocalVersionIdentifiesOnlyThisCLIBuild(t *testing.T) {
	for _, locale := range []string{"en", "es", "pt"} {
		var out, errOut bytes.Buffer
		var info productinfo.Info
		if code := Run([]string{"--lang", locale, "--version"}, &out, &errOut); code != 0 || json.Unmarshal(out.Bytes(), &info) != nil || info != productinfo.Current() || errOut.Len() != 0 {
			t.Fatal("local version output failed")
		}
	}
}

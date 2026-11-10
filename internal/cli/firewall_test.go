package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestFirewallPrefixesAndLocalizedHelp(t *testing.T) {
	for _, locale := range []string{"en", "es", "pt"} {
		var out, errOut bytes.Buffer
		if code := Run([]string{"--lang", locale, "f", "hel"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "--credentials-file") || errOut.Len() != 0 {
			t.Fatal("localized firewall help failed")
		}
	}
	for _, prefix := range []string{"s", "sta", "co", "h", "", "unknown"} {
		if _, ok := uniqueCommand(prefix); ok {
			t.Fatal("ambiguous prefix accepted", prefix)
		}
	}
	for _, prefix := range []string{"lis", "stat", "stag", "val", "comm", "conf", "sav", "roll", "hist"} {
		if _, ok := uniqueCommand(prefix); !ok {
			t.Fatal("unique prefix rejected", prefix)
		}
	}
}
func TestFirewallRejectsUnsafeOptions(t *testing.T) {
	for _, args := range [][]string{{"status", "--insecure"}, {"status", "--credential", "secret"}, {"stage", "--request-file", "-"}, {"commit", "--confirm-seconds", "29"}, {"status", "--url", "a", "--url", "b"}} {
		var out, errOut bytes.Buffer
		if code := RunInput(append([]string{"firewall"}, args...), strings.NewReader(`{}`), &out, &errOut); code != 2 || out.Len() != 0 || strings.Contains(errOut.String(), "secret") {
			t.Fatal("unsafe options accepted")
		}
	}
}

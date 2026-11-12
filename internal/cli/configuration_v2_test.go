package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestConfigurationV2GrammarRejectsAmbiguousAndMixedFlags(t *testing.T) {
	for _, locale := range []string{"en", "es", "pt"} {
		var out, errOut bytes.Buffer
		if RunInput([]string{"--lang", locale, "configuration", "help"}, nil, &out, &errOut) != 0 || !strings.Contains(out.String(), "--operation-id") || errOut.Len() != 0 {
			t.Fatal("localized operation help unavailable", locale)
		}
	}
	for _, args := range [][]string{
		{"c"}, {"s"}, {"validate", "--operation-id", "existing"}, {"status", "--request-file", "-"},
		{"commit", "--confirm-seconds", "0"}, {"commit", "--confirm-seconds", "121"},
		{"commit", "--confirm-seconds", "060"}, {"stage", "--request-file", "/arbitrary/path"},
		{"confirm", "--target", strings.Repeat("a", 64)}, {"operation"}, {"execute"}, {"status", "--token", "private-value"},
	} {
		var out, errOut bytes.Buffer
		full := append([]string{"configuration"}, args...)
		full = append(full, "--url", "https://127.0.0.1:9443", "--ca-file", "missing", "--credentials-file", "missing")
		if RunInput(full, strings.NewReader(`{}`), &out, &errOut) != 2 || out.Len() != 0 || strings.Contains(errOut.String(), "private-value") {
			t.Fatal("invalid v2 grammar accepted", args)
		}
	}
}

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
		{"audit", "--limit", "101"}, {"audit", "--before", "01"}, {"status", "--limit", "5"},
		{"r"}, {"replace-candidate", "--request-file", "-"}, {"discard-candidate"}, {"discard-candidate", "--expected-candidate-stage", "../foreign"}, {"stage", "--expected-candidate-stage", "stage"}, {"discard-candidate", "--expected-candidate-stage", "stage", "--request-file", "-"},
	} {
		var out, errOut bytes.Buffer
		full := append([]string{"configuration"}, args...)
		full = append(full, "--url", "https://127.0.0.1:9443", "--ca-file", "missing", "--credentials-file", "missing")
		if RunInput(full, strings.NewReader(`{}`), &out, &errOut) != 2 || out.Len() != 0 || strings.Contains(errOut.String(), "private-value") {
			t.Fatal("invalid v2 grammar accepted", args)
		}
	}
}

func TestConfigurationCandidateCommandPrefixes(t *testing.T) {
	for input, expected := range map[string]string{"rep": "replace-candidate", "dis": "discard-candidate", "rol": "rollback", "stag": "stage"} {
		if command, ok := configurationCommand(input); !ok || command != expected {
			t.Fatal("prefix", input, command)
		}
	}
	for _, input := range []string{"r", "s", "c"} {
		if _, ok := configurationCommand(input); ok {
			t.Fatal("ambiguous prefix", input)
		}
	}
}

func TestConfigurationReplaceRejectsImplicitOrConflictingCandidateIdentity(t *testing.T) {
	base := []string{"configuration", "replace-candidate", "--request-file", "-", "--url", "https://127.0.0.1:9443", "--ca-file", "not-read", "--credentials-file", "not-read"}
	for _, input := range []string{
		`{"operation":"replace_candidate","config":{"schema_version":4,"default_action":"deny","rules":[]}}`,
		`{"operation":"replace_candidate","expected_candidate_stage_operation_id":"another-stage","config":{"schema_version":4,"default_action":"deny","rules":[]}}`,
		`{"operation":"replace_candidate","local_services_config":{"schema_version":3},"config":{"schema_version":4,"default_action":"deny","rules":[]}}`,
	} {
		for _, locale := range []string{"en", "es", "pt"} {
			args := append([]string{"--lang", locale}, base...)
			if strings.Contains(input, "another-stage") || strings.Contains(input, "local_services_config") {
				args = append(args, "--expected-candidate-stage", "selected-stage")
			}
			var out, errOut bytes.Buffer
			if code := RunInput(args, strings.NewReader(input), &out, &errOut); code != 2 || out.Len() != 0 || !strings.HasPrefix(errOut.String(), "ANDEIVA_INVALID_ARGUMENT:") {
				t.Fatal("invalid candidate input reached transport", locale, out.String(), errOut.String())
			}
		}
	}
}

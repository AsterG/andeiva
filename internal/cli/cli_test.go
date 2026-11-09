package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunLocalizedStatus(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"default", []string{"status"}, "not implemented"},
		{"english", []string{"--lang", "en", "status"}, "not implemented"},
		{"spanish", []string{"--lang", "es", "status"}, "no están implementadas"},
		{"portuguese", []string{"--lang", "pt", "status"}, "não estão implementadas"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(test.args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), test.want) || stderr.Len() != 0 {
				t.Fatalf("unexpected output: stdout %q, stderr %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"-h"}, {"--lang", "es"}, {"--lang", "pt", "help"}} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "andeiva [--lang en|es|pt] [help|status]") || stderr.Len() != 0 {
			t.Fatalf("args %q: exit %d, stdout %q, stderr %q", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestRunRejectsInvalidInputWithoutReflection(t *testing.T) {
	tests := []struct {
		args []string
		code string
	}{
		{[]string{"--lang"}, "ANDEIVA_INVALID_ARGUMENT"},
		{[]string{"--lang", "fr", "help"}, "ANDEIVA_UNSUPPORTED_LOCALE"},
		{[]string{"--lang=en"}, "ANDEIVA_INVALID_ARGUMENT"},
		{[]string{"status", "extra"}, "ANDEIVA_INVALID_ARGUMENT"},
		{[]string{"--lang", "es", "unknown"}, "ANDEIVA_INVALID_ARGUMENT"},
		{[]string{"sh", "-c", "echo unexpected"}, "ANDEIVA_INVALID_ARGUMENT"},
		{[]string{"\x1b[31m"}, "ANDEIVA_INVALID_ARGUMENT"},
	}
	for _, test := range tests {
		var stdout, stderr bytes.Buffer
		if code := Run(test.args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), test.code+":") {
			t.Fatalf("args %q: exit %d, stdout %q, stderr %q", test.args, code, stdout.String(), stderr.String())
		}
		if strings.ContainsAny(stderr.String(), "\x1b\x00") {
			t.Fatalf("terminal control characters reflected: %q", stderr.String())
		}
	}
}

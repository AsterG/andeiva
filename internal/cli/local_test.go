package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/localadmin"
)

func TestLocalHelpAndUnambiguousCommands(t *testing.T) {
	for _, locale := range []string{"en", "es", "pt"} {
		var out, diagnostic bytes.Buffer
		if code := Run([]string{"--lang", locale, "local", "help"}, &out, &diagnostic); code != 0 || !strings.Contains(out.String(), "Commit") && !strings.Contains(out.String(), "commit") {
			t.Fatal(locale, code, diagnostic.String())
		}
	}
	for _, input := range []string{"c", "s", "st", "", "unknown"} {
		if _, ok := localCommand(input); ok {
			t.Fatal("ambiguous or unknown command accepted", input)
		}
	}
	for input, want := range map[string]string{"comm": "commit", "conf": "confirm", "stag": "stage", "stat": "status", "sa": "save", "r": "rollback"} {
		if got, ok := localCommand(input); !ok || got != want {
			t.Fatal(input, got)
		}
	}
}

func TestLocalInputBoundsAndDuplicateOptions(t *testing.T) {
	if _, err := localOptions([]string{"--url", "https://a", "--url", "https://b"}); err == nil {
		t.Fatal("duplicate URL accepted")
	}
	if _, err := localOptions([]string{"--endpoint-id", "recovery"}); err == nil {
		t.Fatal("caller-selected endpoint accepted")
	}
	for _, body := range []string{`{"transaction":{},"principal":"admin"}`, `{"transaction":{"operation":"stage","Operation":"save"}}`, `{} {}`, strings.Repeat(" ", 65537)} {
		var request localadmin.Request
		if localRequestFile("-", strings.NewReader(body), &request) == nil {
			t.Fatal("invalid request accepted")
		}
	}
	var request localadmin.Request
	if err := localRequestFile("-", strings.NewReader(`{"transaction":{"operation":"validate","key":"test","expected_generation":1}}`), &request); err != nil {
		t.Fatal(err)
	}
}

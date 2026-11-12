package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/storagevol"
)

func TestPlanAndLocalizedHelp(t *testing.T) {
	var output bytes.Buffer
	if run(context.Background(), []string{"--authorized-debian-lab", "--operation", "plan"}, &output, 0) != 0 {
		t.Fatal(output.String())
	}
	var plan storagevol.Plan
	if json.Unmarshal(output.Bytes(), &plan) != nil || plan.TotalBytes != 384*1024*1024 || len(plan.Volumes) != 4 {
		t.Fatal("profile")
	}
	for _, lang := range []string{"en", "es", "pt"} {
		output.Reset()
		if run(context.Background(), []string{"--lang", lang, "--help"}, &output, 1000) != 0 || !strings.Contains(output.String(), "--authorized-debian-lab") {
			t.Fatal("localized help", lang)
		}
	}
}
func TestAuthorizationAndMalformedArgumentsHaveNoActions(t *testing.T) {
	for _, args := range [][]string{{}, {"--operation", "prepare"}, {"--authorized-debian-lab", "--operation", "unknown"}, {"--authorized-debian-lab", "--operation", "mount"}, {"--authorized-debian-lab", "--operation", "activate"}, {"--authorized-debian-lab", "--operation", "delete"}, {"--authorized-debian-lab", "--directory", "/dev/sda"}, {"--authorized-debian-lab", "--operation", "plan", "--id", "../escape"}, {"--authorized-debian-lab", "--lang", "xx"}, {"--unknown"}, {strings.Repeat("x", 4097)}} {
		var output bytes.Buffer
		uid := 0
		if len(args) == 0 {
			uid = 1000
		}
		if run(context.Background(), args, &output, uid) == 0 || !strings.Contains(output.String(), "error_code") {
			t.Fatal("invalid request accepted", args)
		}
	}
}

//go:build linux

package main

import (
	"context"
	"errors"
	"github.com/AsterG/andeiva/internal/previewruntime"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestCommandRoleSubprocess(t *testing.T) {
	if mode := os.Getenv("ANDEIVA_PREVIEW_EXIT_TEST"); mode != "" {
		os.Args = []string{"andeiva-preview"}
		switch mode {
		case "keeper":
			os.Args = append(os.Args, "--nft-fixture", "keeper")
		case "invalid":
			// Validation rejects this role before any namespace or network action.
			os.Args = append(os.Args, "--nft-fixture", "probe", "icmp", "18080", "1")
		case "public":
		default:
			os.Exit(99)
		}
		main()
		os.Exit(0)
	}
	for _, test := range []struct {
		mode   string
		code   int
		output string
	}{{"keeper", 0, ""}, {"invalid", 2, ""}, {"public", 1, "ANDEIVA_PREVIEW_UNAVAILABLE\n"}} {
		t.Run(test.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCommandRoleSubprocess$")
			cmd.Env = append(os.Environ(), "ANDEIVA_PREVIEW_EXIT_TEST="+test.mode)
			output, err := cmd.CombinedOutput()
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			if code != test.code || string(output) != test.output {
				t.Fatalf("got status=%d output=%q; want status=%d output=%q", code, output, test.code, test.output)
			}
		})
	}
}

func TestMigrationRolesRejectAdministrativeArguments(t *testing.T) {
	for _, role := range []string{previewruntime.RoutedMigrationPrepareRoleV3, previewruntime.RoutedMigrationSourceRoleV3, previewruntime.RoutedMigrationStateRoleV3, previewruntime.RoutedMigrationInspectRoleV3} {
		if err := run([]string{role, "--config", "/caller/path"}); !errors.Is(err, previewruntime.ErrConfiguration) {
			t.Fatal("role did not reject arguments before config access", role, err)
		}
	}
}

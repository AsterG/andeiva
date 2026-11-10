package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoordinatorLaunchRejectsUntrustedArguments(t *testing.T) {
	run := strings.Repeat("a", 32)
	for _, tc := range []struct {
		name, run, path        string
		restart, host, gateway uint64
	}{
		{"shell", "$(id)", "/var/tmp/andeiva-nft-state-test", 1, 1, 2},
		{"uppercase", strings.Repeat("A", 32), "/var/tmp/andeiva-nft-state-test", 1, 1, 2},
		{"traversal", run, "/var/tmp/andeiva-nft-state-test/../other", 1, 1, 2},
		{"outside", run, "/tmp/andeiva-nft-state-test", 1, 1, 2},
		{"missing", run, "/var/tmp/andeiva-nft-state-nonexistent-launch-test", 1, 1, 2},
		{"host", run, "/var/tmp/andeiva-nft-state-test", 1, 1, 1},
		{"zero", run, "/var/tmp/andeiva-nft-state-test", 0, 1, 2},
		{"overflow", run, "/var/tmp/andeiva-nft-state-test", 1 << 32, 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := coordinatorCommand(context.Background(), tc.run, tc.path, tc.restart, tc.host, tc.gateway); err == nil {
				t.Fatal("accepted unsafe launch")
			}
		})
	}
}

func TestCoordinatorLaunchDirectoryBoundary(t *testing.T) {
	dir, err := os.MkdirTemp("/var/tmp", "andeiva-nft-state-launch-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	run := strings.Repeat("a", 32)
	if os.Getuid() == 1000 && os.Getgid() == 1000 {
		cmd, err := coordinatorCommand(context.Background(), run, dir, 1, 1, 2)
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Path != "/proc/self/exe" || len(cmd.Args) != 6 || cmd.Args[4] != "4294967296" {
			t.Fatalf("unexpected launch: %v", cmd.Args)
		}
	} else if _, err := coordinatorCommand(context.Background(), run, dir, 1, 1, 2); err == nil {
		t.Fatal("accepted wrong owner")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinatorCommand(context.Background(), run, dir, 1, 1, 2); err == nil {
		t.Fatal("accepted public directory")
	}
	link := filepath.Join("/var/tmp", "andeiva-nft-state-link-"+filepath.Base(dir))
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	if _, err := coordinatorCommand(context.Background(), run, link, 1, 1, 2); err == nil {
		t.Fatal("accepted symlink")
	}
}

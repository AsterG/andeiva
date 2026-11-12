//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestV2BootProcessExitWithPersistentSimulatedEngines(t *testing.T) {
	if os.Getenv("ANDEIVA_V2_BOOT_CHILD") == "1" {
		area, err := os.OpenRoot(os.Getenv("ANDEIVA_V2_BOOT_STATE"))
		if err != nil {
			os.Exit(75)
		}
		components, err := os.OpenRoot(os.Getenv("ANDEIVA_V2_BOOT_COMPONENTS"))
		if err != nil {
			os.Exit(76)
		}
		store, err := openV2(area, v2Budget{Bytes: 8 << 30, Inodes: 2 << 20})
		if err != nil {
			os.Exit(77)
		}
		fw, local := persistentCoordinatorV2Engines(components)
		_, _ = openCoordinatorV2(context.Background(), store, fw, local, v2CoordinatorOptions{ManualTimeout: true, BootID: ptrBootV2(testBootIDV2), Hook: func(point string) error {
			if point == os.Getenv("ANDEIVA_V2_BOOT_POINT") {
				os.Exit(74)
			}
			return nil
		}})
		os.Exit(78)
	}
	for _, point := range []string{"before_boot_intent", "after_boot_intent", "after_boot_engine", "after_boot_readback", "after_boot_completion"} {
		t.Run(point, func(t *testing.T) {
			seed, area, _, _ := bootFixtureV2(t)
			original := clone(seed.store.state)
			components, _ := checkpointFixtureArea(t)
			for _, name := range []string{"fw-first", "fw-second", "local-only"} {
				hash := original.Configuration.Firewall.Running.Hash
				if name == "local-only" {
					hash = original.Configuration.LocalServices.Running.Hash
				}
				if err := components.WriteFile(name+".hash", []byte(hash), 0600); err != nil {
					t.Fatal(err)
				}
			}
			seed.close()
			if err := seed.store.close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestV2BootProcessExitWithPersistentSimulatedEngines$")
			child.Env = append(os.Environ(), "ANDEIVA_V2_BOOT_CHILD=1", "ANDEIVA_V2_BOOT_STATE="+area.Name(), "ANDEIVA_V2_BOOT_COMPONENTS="+components.Name(), "ANDEIVA_V2_BOOT_POINT="+point)
			output, err := child.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 74 {
				t.Fatalf("child did not exit at boundary: %v %s", err, output)
			}
			store, err := openV2(area, seed.store.budget)
			if err != nil {
				t.Fatal(err)
			}
			defer store.close()
			before := store.selection.Sequence
			fw, local := persistentCoordinatorV2Engines(components)
			c, err := openCoordinatorV2(context.Background(), store, fw, local, v2CoordinatorOptions{ManualTimeout: true, BootID: ptrBootV2(testBootIDV2)})
			if err != nil {
				t.Fatal(err)
			}
			defer c.close()
			if store.state.Generation != original.Generation+1 || store.state.Configuration.Running.Hash != original.Configuration.Startup.Hash || !c.readback(*store.state.Configuration) {
				t.Fatal("process-exit recovery did not verify Startup")
			}
			if point == "after_boot_completion" && store.selection.Sequence != before {
				t.Fatal("completion/marker gap repeated publication")
			}
		})
	}
}

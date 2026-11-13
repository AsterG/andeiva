//go:build linux

package previewruntime

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRoutedRetirementSlotV3UnprivilegedRefusal(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("unprivileged refusal only")
	}
	area, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	if _, err = openRoutedRetirementSlotV3(area); err == nil {
		t.Fatal("unprivileged retirement writer accepted")
	}
}

func TestRoutedRetirementSlotV3Native(t *testing.T) {
	if os.Getenv("ANDEIVA_ROUTED_LINKS_NATIVE") != "1" {
		t.Skip("explicit isolated root filesystem qualification only")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getenv("CI") != "" {
		t.Fatal("isolated root qualification required")
	}
	for _, scenario := range []string{"complete", "short", "corrupt", "mode", "hardlink", "symlink", "fifo"} {
		t.Run(scenario, func(t *testing.T) {
			path := t.TempDir()
			if err := os.Chmod(path, 0700); err != nil {
				t.Fatal(err)
			}
			area, err := os.OpenRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			defer area.Close()
			slot, err := openRoutedRetirementSlotV3(area)
			if err != nil {
				t.Fatal(err)
			}
			defer slot.Close()
			if second, err := openRoutedRetirementSlotV3(area); err == nil {
				second.Close()
				t.Fatal("simultaneous writer accepted")
			}
			initial := make([]byte, RootRetirementReceiptSizeV3)
			if _, err = slot.file.ReadAt(initial, 0); err != nil || !bytes.Equal(initial, make([]byte, len(initial))) {
				t.Fatal("preallocation is not an unissued slot", err)
			}
			ids := Identities{SchemaVersion: 1, APIUID: 62001, APIGID: 62001, HelperUID: 62002, IPCGID: 62003}
			m := Metadata{SchemaVersion: RoutedMetadataSchemaVersion, RunID: strings.Repeat("a", 32), BootID: "12345678-1234-1234-1234-123456789abc", HostNamespace: 40, GatewayNamespace: 42}
			if err = slot.recordDrained(m, ids); err != nil {
				t.Fatal(err)
			}
			raw, err := area.ReadFile(routedRetirementSlotV3)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := DecodeRootRetirementReceiptV3(raw)
			if err != nil || receipt.Old.Namespace != m.GatewayNamespace || receipt.Old.RunID != m.RunID || receipt.DrainedAtBootNS <= 0 {
				t.Fatal("invalid persisted witness", err)
			}
			if err = slot.Close(); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(path, routedRetirementSlotV3)
			switch scenario {
			case "short":
				err = os.Truncate(name, 100)
			case "corrupt":
				raw[0] = '!'
				err = os.WriteFile(name, raw, 0600)
			case "mode":
				err = os.Chmod(name, 0640)
			case "hardlink":
				err = os.Link(name, filepath.Join(path, "retained"))
			case "symlink", "fifo":
				err = os.Rename(name, filepath.Join(path, "retained"))
				if err == nil && scenario == "symlink" {
					err = os.Symlink("retained", name)
				} else if err == nil {
					err = unix.Mkfifo(name, 0600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := openRoutedRetirementSlotV3(area)
			if scenario == "complete" {
				if err != nil {
					t.Fatal(err)
				}
				reopened.Close()
			} else if err == nil {
				reopened.Close()
				t.Fatal("invalid retirement slot adopted")
			}
			if scenario == "symlink" || scenario == "fifo" || scenario == "hardlink" {
				retained, err := os.ReadFile(filepath.Join(path, "retained"))
				if err != nil || !bytes.Equal(retained, raw) {
					t.Fatal("retained evidence changed", err)
				}
			}
		})
	}
}

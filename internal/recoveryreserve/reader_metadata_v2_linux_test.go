//go:build linux

package recoveryreserve

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadOnlyV2MetadataUsesExactProfile(t *testing.T) {
	for _, kind := range []string{"valid", "oversize", "mode", "symlink", "hardlink", "wrong_inode", "basename"} {
		t.Run(kind, func(t *testing.T) {
			area, access, path := sharedAreaV2(t)
			name := "bounded.json"
			if err := os.WriteFile(filepath.Join(path, name), []byte("{}"), 0640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(path, name), 0640); err != nil {
				t.Fatal(err)
			}
			limit := int64(2)
			switch kind {
			case "oversize":
				limit = 1
			case "mode":
				if err := os.Chmod(filepath.Join(path, name), 0660); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(name, filepath.Join(path, "link")); err != nil {
					t.Fatal(err)
				}
				name = "link"
			case "hardlink":
				if err := os.Link(filepath.Join(path, name), filepath.Join(path, "link")); err != nil {
					t.Fatal(err)
				}
			case "wrong_inode":
				access.Inode++
			case "basename":
				name = "../bounded.json"
			}
			info, err := access.CheckFile(area, name, limit)
			if kind == "valid" {
				if err != nil || info.Size() != 2 {
					t.Fatal(info, err)
				}
			} else if err == nil {
				t.Fatal("invalid metadata accepted", kind)
			}
		})
	}
}

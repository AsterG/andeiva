//go:build linux

package previewruntime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRoutedCutoverV3NeverFallsBack(t *testing.T) {
	for _, kind := range []string{"absent", "valid", "truncated", "directory", "dangling-link"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "grouped-cutover.json")
			var err error
			switch kind {
			case "valid":
				err = os.WriteFile(path, []byte(`{"version":1}`), 0600)
			case "truncated":
				err = os.WriteFile(path, []byte(`{"version":`), 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "dangling-link":
				err = os.Symlink(filepath.Join(t.TempDir(), "missing"), path)
			}
			if err != nil {
				t.Fatal(err)
			}
			actual := legacyRuntimeAllowedAtV3(path)
			if kind == "absent" {
				if actual != nil {
					t.Fatal(actual)
				}
			} else if !errors.Is(actual, ErrConfiguration) {
				t.Fatalf("%s permitted legacy fallback: %v", kind, actual)
			}
		})
	}
}

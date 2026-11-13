//go:build linux

package previewruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoutedCutoverV3PinsOperationalManifests(t *testing.T) {
	deployment, links := []byte("deployment\n"), []byte("node-links\n")
	digest, linkDigest := sha256.Sum256(deployment), sha256.Sum256(links)
	marker, _ := json.Marshal(routedCutoverRecordV3{1, hex.EncodeToString(digest[:]), hex.EncodeToString(linkDigest[:])})
	if err := verifyRoutedCutoverV3(marker, deployment, links); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct{ marker, deployment, links []byte }{
		{marker, []byte("other"), links}, {marker, deployment, []byte("other")},
		{[]byte(`{"version":1}`), deployment, links}, {marker, nil, links},
		{append(marker, []byte(" {}")...), deployment, links},
		{[]byte(strings.Replace(string(marker), `"version":1`, `"version":1,"version":1`, 1)), deployment, links},
	} {
		if verifyRoutedCutoverV3(input.marker, input.deployment, input.links) == nil {
			t.Fatal("unbound cutover accepted")
		}
	}
}

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

//go:build !linux

package trafficprobe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedCARefusesEveryPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("untrusted"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, path + ".absent", "", "relative", `\\.\pipe\andeiva-ca-test`} {
		file, err := openCAFile(name)
		if file != nil || err != errInvalid {
			t.Fatalf("unsafe opener result for %q", name)
		}
		pool, err := readCA(name)
		if pool != nil || err != errInvalid {
			t.Fatalf("unsafe loader result for %q", name)
		}
	}
}

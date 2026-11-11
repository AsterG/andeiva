//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The external fixtures are public signed messages; no private key enters source.
func TestNativeSQVTrustedAlteredAndForeignSignature(t *testing.T) {
	trustedPath := os.Getenv("ANDEIVA_TEST_DEBIAN_RELEASE")
	foreignPath := os.Getenv("ANDEIVA_TEST_FOREIGN_RELEASE")
	if trustedPath == "" || foreignPath == "" {
		t.Skip("native signature gate needs a public Debian InRelease and a valid foreign-signed fixture")
	}
	dir := t.TempDir()
	trusted, err := os.ReadFile(trustedPath)
	if err != nil || len(trusted) > 1<<20 {
		t.Fatal("invalid public Debian fixture", err)
	}
	foreign, err := os.ReadFile(foreignPath)
	if err != nil || len(foreign) > 1<<20 {
		t.Fatal("invalid public foreign fixture", err)
	}
	altered := bytes.Replace(trusted, []byte("Origin: Debian"), []byte("Origin: Altered"), 1)
	if bytes.Equal(trusted, altered) {
		t.Fatal("trusted fixture does not contain the expected signed field")
	}
	for name, body := range map[string][]byte{"trusted": trusted, "altered": altered, "foreign": foreign} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	verified, err := runFile(root, "trusted", true)
	if err != nil || !bytes.Contains(verified, []byte("Codename: trixie\n")) {
		t.Fatal("actual Debian signature did not authenticate its cleartext", err)
	}
	for _, name := range []string{"altered", "foreign"} {
		if _, err := runFile(root, name, true); err == nil {
			t.Fatalf("actual sqv accepted %s signature", name)
		}
	}
}

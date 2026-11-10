//go:build linux

package adminclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialsFileProtection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	body := []byte(`{"username":"alice","credential":"` + strings.Repeat("a", 64) + `"}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentials(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentials(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentials(path); err == nil {
		t.Fatal("public file accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hardlink")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentials(path); err == nil {
		t.Fatal("hardlink accepted")
	}
	if _, err := ReadCredentials(dir); err == nil {
		t.Fatal("directory accepted")
	}
}

//go:build linux

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// The release callback is simulated here; actual signatures have a separate gate.
func TestClosedInventoryIDBindsScriptsAndChecker(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"archives", "provenance", "bin", "docs", "licenses"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{}
	for _, name := range []string{"install.sh", "install-in-namespace.sh", "capture.sh", "bin/check", "README.md", "DESIGN.md", "docs/en.md", "docs/es.md", "docs/pt.md", "LICENSE", "NOTICE", "licenses/GO-LICENSE"} {
		files[name] = []byte("fixture\n")
	}
	version := "0.1.0~alpha901"
	manifestText := "ANDEIVA_BOOT_OFFLINE_V1\t" + version + "\t1794355200\n"
	for index, name := range []string{"andeiva-boot-branding", "andeiva-boot-activation"} {
		stage := t.TempDir()
		if err := os.Mkdir(filepath.Join(stage, "DEBIAN"), 0o755); err != nil {
			t.Fatal(err)
		}
		arch := "all"
		control := "Package: " + name + "\nVersion: " + version + "\nMaintainer: ASTERG\nSection: admin\nPriority: optional\nDescription: Fixture\n"
		if index == 1 {
			arch = "amd64"
			control += "Homepage: https://github.com/AsterG/andeiva\nX-Andeiva-Offline-Install-Guard: 1\nDepends: andeiva-boot-branding (= " + version + "), plymouth (= 24.004.60-5), plymouth-themes (= 24.004.60-5), initramfs-tools (= 0.148.4), grub-pc\n"
		}
		control += "Architecture: " + arch + "\n"
		for leaf, body := range map[string]string{"control": control, "md5sums": ""} {
			if err := os.WriteFile(filepath.Join(stage, "DEBIAN", leaf), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		archive := fmt.Sprintf("archives/%04d.deb", index+1)
		cmd := exec.Command("/usr/bin/dpkg-deb", "--build", "--root-owner-group", stage, filepath.Join(dir, archive))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build fixture: %v %s", err, output)
		}
		body, err := os.ReadFile(filepath.Join(dir, archive))
		if err != nil {
			t.Fatal(err)
		}
		files[archive] = body
		manifestText += fmt.Sprintf("%s\tproduct\t%s\t%s\t%s\t%x\n", archive, name, version, arch, sha256.Sum256(body))
	}
	files["manifest.tsv"] = []byte(manifestText)
	for _, suite := range suites {
		files["provenance/"+suite+".InRelease"] = []byte("simulated signature callback\n")
		files["provenance/"+suite+".Packages"] = nil
	}
	writeInventory := func() {
		t.Helper()
		var names []string
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
			names = append(names, name)
		}
		sort.Strings(names)
		var sums strings.Builder
		for _, name := range names {
			fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(files[name]), name)
		}
		if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeInventory()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	authenticate := func(name string) ([]byte, error) {
		suite := strings.TrimSuffix(strings.TrimPrefix(name, "provenance/"), ".InRelease")
		return fmt.Appendf(nil, "Codename: %s\nDate: Wed, 11 Nov 2026 00:00:00 UTC\nValid-Until: Thu, 12 Nov 2026 00:00:00 UTC\nSHA256:\n %x 0 main/binary-amd64/Packages\n", suite, sha256.Sum256(nil)), nil
	}
	previous, err := verify(root, authenticate, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"install.sh", "bin/check"} {
		files[name] = []byte("changed fixture\n")
		if err := os.WriteFile(filepath.Join(dir, name), files[name], 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := verify(root, authenticate, now); err == nil {
			t.Fatal("changed payload accepted against stale inventory")
		}
		writeInventory()
		next, err := verify(root, authenticate, now)
		if err != nil || next == previous {
			t.Fatalf("changed %s kept bundle identity: %v", name, err)
		}
		previous = next
	}
}

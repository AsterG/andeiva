package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureManifest(t *testing.T) (*os.Root, manifest) {
	t.Helper()
	dir := t.TempDir()
	data := "ANDEIVA_BOOT_OFFLINE_V1\t0.1.0~alpha901\t1794355200\n"
	for number, name := range []string{"andeiva-boot-branding", "andeiva-boot-activation", "fontconfig"} {
		origin, version := "product", "0.1.0~alpha901"
		hash := strings.Repeat("a", 64)
		arch := "amd64"
		if number == 0 {
			arch = "all"
		}
		if number == 2 {
			want := dependencyProfile[name]
			origin, version, arch, hash = "debian", want.version, want.arch, want.hash
		}
		data += fmt.Sprintf("archives/%04d.deb\t%s\t%s\t%s\t%s\t%s\n", number+1, origin, name, version, arch, hash)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.tsv"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	m, _, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, m
}

func TestManifestStrictFieldsNoPrivatePaths(t *testing.T) {
	for _, change := range []string{"duplicate", "private-path", "origin", "version", "missing-product"} {
		t.Run(change, func(t *testing.T) {
			root, _ := fixtureManifest(t)
			data, _ := root.ReadFile("manifest.tsv")
			text := string(data)
			switch change {
			case "duplicate":
				text += strings.Split(text, "\n")[1] + "\n"
			case "private-path":
				text = strings.Replace(text, "archives/0001.deb", "/home/operator/private.deb", 1)
			case "origin":
				text = strings.Replace(text, "\tproduct\t", "\tdebian\t", 1)
			case "version":
				text = strings.Replace(text, "ANDEIVA_BOOT_OFFLINE_V1\t0.1.0~alpha901", "ANDEIVA_BOOT_OFFLINE_V1\tlatest", 1)
			case "missing-product":
				text = strings.Replace(text, "andeiva-boot-activation", "unrelated-package", 1)
			}
			if err := root.WriteFile("manifest.tsv", []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := load(root); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}

func TestSimulationOnlyExpectedNewPackages(t *testing.T) {
	_, m := fixtureManifest(t)
	i := m.Items[2]
	valid := fmt.Sprintf("Inst %s (%s Debian:13/stable [%s])\nConf %s (%s Debian:13/stable [%s])\n", i.Name, i.Version, i.Arch, i.Name, i.Version, i.Arch)
	if err := plan(m, strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"Remv systemd [1.0]\n", fmt.Sprintf("Inst %s [0.9-1] (%s Debian [amd64])\n", i.Name, i.Version), "Inst unrelated (1.0 Debian [amd64])\n", fmt.Sprintf("Inst %s (9999 Debian [amd64])\n", i.Name), strings.Repeat(" ", 70000) + "\nRemv systemd\n"} {
		if err := plan(m, strings.NewReader(bad)); err == nil {
			t.Fatal("unsafe or truncated plan accepted")
		}
	}
}

func TestSignedReleaseBodyBoundsAndExpiry(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	valid := "Codename: trixie\nDate: Wed, 11 Nov 2026 00:00:00 UTC\nValid-Until: Thu, 12 Nov 2026 00:00:00 UTC\nSHA256:\n " + strings.Repeat("a", 64) + " 0 main/binary-amd64/Packages\n"
	if _, _, err := releaseProof([]byte(valid), now, "trixie"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(valid, "12 Nov", "10 Nov", 1), strings.Replace(valid, "Codename: trixie", "Codename: bookworm", 1), strings.Replace(valid, "Date: Wed, 11 Nov 2026 00:00:00 UTC\n", "", 1), valid + "Valid-Until: Thu, 12 Nov 2026 00:00:00 UTC\n", strings.Replace(valid, "Date: Wed, 11 Nov", "Date: Fri, 13 Nov", 1)} {
		if _, _, err := releaseProof([]byte(bad), now, "trixie"); err == nil {
			t.Fatal("invalid release body accepted")
		}
	}
	order := strings.Replace(valid, "Date: Wed, 11 Nov 2026 00:00:00 UTC", "Date: Wed, 11 Nov 2026 12:00:00 UTC", 1)
	order = strings.Replace(order, "Valid-Until: Thu, 12 Nov 2026 00:00:00 UTC", "Valid-Until: Wed, 11 Nov 2026 06:00:00 UTC", 1)
	if _, _, err := releaseProof([]byte(order), now, "trixie"); err == nil {
		t.Fatal("release date later than unexpired validity accepted")
	}
}

func TestReleaseExpiryRequiredForUpdatingSuites(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	for _, suite := range []string{"trixie", "trixie-updates", "trixie-security"} {
		body := "Codename: " + suite + "\nDate: Wed, 11 Nov 2026 00:00:00 UTC\nSHA256:\n " + strings.Repeat("a", 64) + " 0 main/binary-amd64/Packages\n"
		_, _, err := releaseProof([]byte(body), now, suite)
		if (err == nil) != (suite == "trixie") {
			t.Fatalf("missing expiry for %s: %v", suite, err)
		}
		if _, _, err := releaseProof([]byte(body+"Valid-Until: Thu, 12 Nov 2026 00:00:00 UTC\n"), now, suite); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProductPackageCannotCarryInstallHooks(t *testing.T) {
	want := item{Name: "andeiva-boot-branding", Version: "0.1.0~alpha901", Arch: "all"}
	control := "Package: andeiva-boot-branding\nVersion: 0.1.0~alpha901\nArchitecture: all\nMaintainer: ASTERG\nSection: admin\nPriority: optional\nDescription: Fixture\n Test only.\n"
	for _, hook := range []bool{false, true} {
		var data bytes.Buffer
		writer := tar.NewWriter(&data)
		names := []string{"control", "md5sums"}
		if hook {
			names = append(names, "postinst")
		}
		for _, name := range names {
			body := "x"
			if name == "control" {
				body = control
			}
			if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(body))}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		err := productControl(data.Bytes(), want)
		if hook && err == nil || !hook && err != nil {
			t.Fatalf("hook guard failed: %v", err)
		}
	}
	for _, extra := range []string{"Conflicts: grub-pc\n", "Essential: yes\n", "Package: unrelated\n", "Depends: unrelated\n", "Homepage: https://invalid.example\n"} {
		if err := productFields([]byte(control+extra), want); err == nil {
			t.Fatalf("unexpected product metadata accepted: %q", extra)
		}
	}
}

func TestExistingActivatorCapabilityStrict(t *testing.T) {
	for _, valid := range []string{`{"offline_install_guard":1}`, "{ \"offline_install_guard\" : 1 }\n"} {
		if err := capabilities(strings.NewReader(valid)); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{`{}`, `{"offline_install_guard":0}`, `{"offline_install_guard":"1"}`, `{"offline_install_guard":1,"offline_install_guard":1}`, `{"offline_install_guard":1,"extra":true}`, `{"offline_install_guard":1} {}`, strings.Repeat(" ", 4097)} {
		if err := capabilities(strings.NewReader(bad)); err == nil {
			t.Fatalf("unsupported capability accepted: %q", bad)
		}
	}
}

func TestIndexedPackageRequiresExactAuthenticatedHash(t *testing.T) {
	root, _ := fixtureManifest(t)
	body := "fixture bytes"
	digest := sha256.Sum256([]byte(body))
	hash := hex.EncodeToString(digest[:])
	index := "Package: libfixture1\nVersion: 1.0-1\nArchitecture: amd64\nSHA256: " + hash + "\n\n"
	if err := root.WriteFile("Packages", []byte(index), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{hash, strings.Repeat("b", 64)} {
		found := map[string]bool{}
		needed := map[string]item{"libfixture1": {Name: "libfixture1", Version: "1.0-1", Arch: "amd64", Hash: expected}}
		if err := packageProof(root, "Packages", needed, found); err != nil {
			t.Fatal(err)
		}
		if found["libfixture1"] != (expected == hash) {
			t.Fatal("package hash proof mismatch")
		}
	}
}

func TestClosedTreeRejectsUnexpectedDirectoriesAndLinks(t *testing.T) {
	for _, mutation := range []string{"none", "extra-file", "extra-directory", "link", "many-files"} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			for _, directory := range []string{"archives", "provenance", "bin", "docs", "licenses"} {
				if err := os.Mkdir(filepath.Join(dir, directory), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "manifest.tsv"), []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "extra-file":
				if err := os.WriteFile(filepath.Join(dir, "private-status"), []byte("excluded"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "extra-directory":
				if err := os.Mkdir(filepath.Join(dir, "docs", "nested"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := os.Symlink("../manifest.tsv", filepath.Join(dir, "docs", "link")); err != nil {
					t.Fatal(err)
				}
			case "many-files":
				for i := range 32 {
					if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%02d", i)), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			err = tree(root, map[string]bool{"manifest.tsv": true})
			if (err == nil) != (mutation == "none") {
				t.Fatalf("tree guard mismatch: %v", err)
			}
		})
	}
}

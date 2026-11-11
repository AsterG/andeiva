package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestCompiledDependencyProfileAcceptsOnlyReviewedTuples(t *testing.T) {
	if len(dependencyProfile) != 26 || len(baselineProfile) != 6 {
		t.Fatal("qualification profile changed without its contract")
	}
	for name, want := range dependencyProfile {
		i := item{Name: name, Version: want.version, Arch: want.arch, Hash: want.hash}
		if !qualifiedDependency(i) {
			t.Fatal("reviewed tuple refused")
		}
		for _, mutate := range []func(*item){func(i *item) { i.Version += "+changed" }, func(i *item) { i.Hash = strings.Repeat("0", 64) }, func(i *item) { i.Arch = "arm64" }} {
			changed := i
			mutate(&changed)
			if qualifiedDependency(changed) {
				t.Fatal("changed tuple accepted")
			}
		}
	}
	for _, name := range []string{"linux-image-amd64", "grub-pc", "initramfs-tools", "openssh-server", "network-manager"} {
		if qualifiedDependency(item{Name: name, Version: "1", Arch: "amd64", Hash: strings.Repeat("a", 64)}) {
			t.Fatalf("unqualified package accepted: %s", name)
		}
	}
}

func TestManifestAllowsReviewedSubsetOrFull26ButNoExtras(t *testing.T) {
	root, _ := fixtureManifest(t)
	data, err := root.ReadFile("manifest.tsv")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	prefix := strings.Join(lines[:3], "\n") + "\n"
	var names []string
	for name := range dependencyProfile {
		names = append(names, name)
	}
	sort.Strings(names)
	full := prefix
	for index, name := range names {
		i := dependencyProfile[name]
		full += fmt.Sprintf("archives/%04d.deb\tdebian\t%s\t%s\t%s\t%s\n", index+3, name, i.version, i.arch, i.hash)
	}
	if err := root.WriteFile("manifest.tsv", []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	if m, _, err := load(root); err != nil || len(m.Items) != 28 {
		t.Fatal("full profile refused", err)
	}
	bad := full + fmt.Sprintf("archives/0029.deb\tdebian\tgrub-pc\t2.12-9+deb13u2\tamd64\t%s\n", strings.Repeat("a", 64))
	if err := root.WriteFile("manifest.tsv", []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := load(root); err == nil {
		t.Fatal("signed-package provenance cannot authorize an extra profile package")
	}
}

func TestBaselineRequiresExactInstalledBootPackages(t *testing.T) {
	for _, mutation := range []string{"none", "missing", "version", "architecture", "unconfigured", "duplicate"} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			var paragraphs []string
			for name, want := range baselineProfile {
				paragraphs = append(paragraphs, fmt.Sprintf("Package: %s\nStatus: install ok installed\nVersion: %s\nArchitecture: %s\n", name, want.version, want.arch))
			}
			sort.Strings(paragraphs)
			switch mutation {
			case "missing":
				paragraphs = paragraphs[1:]
			case "version":
				paragraphs[0] = strings.Replace(paragraphs[0], "Version: 2.12-9+deb13u2", "Version: 2.12-9+deb13u3", 1)
			case "architecture":
				paragraphs[0] = strings.Replace(paragraphs[0], "amd64", "arm64", 1)
			case "unconfigured":
				paragraphs[0] = strings.Replace(paragraphs[0], "install ok installed", "install ok unpacked", 1)
			case "duplicate":
				paragraphs = append(paragraphs, paragraphs[0])
			}
			if err := os.WriteFile(filepath.Join(dir, "status"), []byte(strings.Join(paragraphs, "\n")), 0o600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			err = baseline(root)
			if (err == nil) != (mutation == "none") {
				t.Fatalf("baseline %s: %v", mutation, err)
			}
		})
	}
}

func TestAPTCacheNameQuotesEpochWithLowercaseHex(t *testing.T) {
	if got := cacheName(item{Name: "fixture", Version: "1:1", Arch: "all"}); got != "fixture_1%3a1_all.deb" {
		t.Fatal(got)
	}
	if got := cacheName(item{Name: "fixture", Version: "1_2", Arch: "all"}); got != "fixture_1%5f2_all.deb" {
		t.Fatal(got)
	}
}

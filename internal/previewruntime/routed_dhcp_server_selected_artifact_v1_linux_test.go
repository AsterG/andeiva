//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/AsterG/andeiva/internal/dhcpkea"
)

func TestRoutedDHCPServerSelectedArtifactV1Native(t *testing.T) {
	if os.Getenv("ANDEIVA_NATIVE_DHCP_SERVER_ARTIFACT_V1") != "1" || os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Skip("requires the dedicated Debian laboratory and its Kea account")
	}
	ctx := context.Background()
	uid, gid, err := routedDHCPServerAccountV1()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	runtime := filepath.Join(base, "runtime")
	registry := filepath.Join(base, "registry")
	for _, dir := range []string{runtime, registry, filepath.Join(registry, "leases")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	leasePath := filepath.Join(registry, "leases")
	if err := os.Chown(leasePath, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	directory, err := os.OpenRoot(runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	registryFile, err := os.Open(registry)
	if err != nil {
		t.Fatal(err)
	}
	defer registryFile.Close()
	leases, err := os.Open(leasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer leases.Close()
	selected := selectedDHCPServerBindingFixtureV1(t)
	wrong := selected
	wrong.Reference.Mode = "pending"
	if out, err := compileRoutedDHCPServerSelectedArtifactV1(ctx, selected.Identity, selected.Work, wrong, directory, registryFile, leases, 1<<20); !errors.Is(err, ErrIdentity) || out != nil {
		t.Fatal("prepared an artifact from a pending selection", err)
	}
	if entries, err := os.ReadDir(registry); err != nil || len(entries) != 1 || entries[0].Name() != "leases" {
		t.Fatal("rejected selection modified operational storage", err)
	}
	var first []uint32
	for cycle := range 2 {
		prepared, err := compileRoutedDHCPServerSelectedArtifactV1(ctx, selected.Identity, selected.Work, selected, directory, registryFile, leases, 1<<20)
		if err != nil {
			t.Fatal("compile the verified active Kea selection", err)
		}
		t.Cleanup(func() { _ = prepared.closeV1() })
		artifact, err := dhcpkea.Compile(prepared.config, prepared.bindings)
		if err != nil || !artifact.Enabled || routedDHCPServerConfigFileV1(prepared.file, artifact.JSON, gid) != nil {
			t.Fatal("selected artifact is not an exact read-only Kea descriptor", err)
		}
		if cycle == 0 {
			for _, binding := range prepared.bindings {
				first = append(first, binding.SubnetID)
			}
		} else {
			for i, binding := range prepared.bindings {
				if binding.SubnetID != first[i] {
					t.Fatal("runtime artifact retirement changed a durable subnet ID")
				}
			}
		}
		if err := prepared.closeV1(); err != nil {
			t.Fatal(err)
		}
		if entries, err := os.ReadDir(runtime); err != nil || len(entries) != 0 {
			t.Fatal("retirement left active Kea configuration", err)
		}
	}
	if info, err := os.Stat(leasePath); err != nil || !info.IsDir() {
		t.Fatal("retirement removed the lease directory", err)
	}
}

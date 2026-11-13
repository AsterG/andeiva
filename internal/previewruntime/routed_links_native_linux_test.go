//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRoutedGatewayLinksV3Native(t *testing.T) {
	if os.Getenv("ANDEIVA_ROUTED_LINKS_NATIVE") != "1" {
		t.Skip("explicit isolated Debian link qualification only")
	}
	if os.Getenv("CI") != "" || os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("native identity")
	}
	version, err := os.ReadFile("/proc/version")
	if err != nil || strings.Contains(strings.ToLower(string(version)), "microsoft") {
		t.Fatal("native platform")
	}
	release, err := os.ReadFile("/etc/os-release")
	if err != nil || !strings.Contains(string(release), "ID=debian\n") || !strings.Contains(string(release), "VERSION_ID=\"13\"\n") {
		t.Fatal("native Debian 13 required")
	}
	host := os.NewFile(3, "isolated-parent-namespace")
	defer host.Close()
	area, err := os.OpenRoot("/proc/self/fd/4")
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	owned, err := CreateRoutedGatewayNamespaceV3(context.Background(), area)
	if err != nil {
		t.Fatal("namespace creation", err)
	}
	defer func() {
		if err := owned.Close(); err != nil {
			t.Error("namespace cleanup", err)
		}
	}()
	target := owned.File()
	var hs, ts unix.Stat_t
	if unix.Fstat(3, &hs) != nil || unix.Fstat(int(target.Fd()), &ts) != nil || hs.Ino == ts.Ino || ts.Ino != owned.ID() {
		t.Fatal("namespace pins")
	}
	if _, err := CreateRoutedGatewayNamespaceV3(context.Background(), area); err == nil {
		t.Fatal("existing namespace adopted")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	m := Metadata{SchemaVersion: RoutedMetadataSchemaVersion, RunID: "deaddeaddeaddeadbeefbeefbeefbeef", BootID: strings.TrimSpace(string(boot)), HostNamespace: hs.Ino, GatewayNamespace: ts.Ino}
	var bindings [2]RoutedParentLinkV3
	for i, name := range []string{"lan-parent", "wan-parent"} {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatal(err)
		}
		bindings[i] = RoutedParentLinkV3{Index: iface.Index, Name: name, MAC: iface.HardwareAddr.String(), MTU: iface.MTU}
	}
	ctx := context.Background()
	linkIdentity := "ffeeddccbbaa99887766554433221100"
	l, err := NewRoutedGatewayLinksV3(ctx, m, host, target, bindings, linkIdentity)
	if err != nil {
		t.Fatal("constructor", err)
	}
	nextMetadata := m
	nextMetadata.RunID = "00112233445566778899aabbccddeeff"
	next, err := NewRoutedGatewayLinksV3(ctx, nextMetadata, host, target, bindings, linkIdentity)
	if err != nil || next.macs != l.macs {
		t.Fatal("per-run metadata changed persistent interface bindings", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	if err = l.Create(ctx); err != nil {
		t.Fatal("create", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			t.Error("cleanup", err)
		}
	}()
	for i := range bindings {
		owned := l.created[i]
		if owned == nil || owned.Info.Kind != "macvlan" || owned.Info.Data.Mode != "private" || containsRoutedLinkFlagV3(owned.Flags, "UP") {
			t.Fatal("child not private/down")
		}
		if _, err := net.InterfaceByName(routedLinkNameV3(i)); err == nil {
			t.Fatal("child leaked into parent namespace")
		}
	}
	if err = l.parentsMatch(ctx); err != nil {
		t.Fatal("parent changed", err)
	}
	if err = l.Close(); err != nil {
		t.Fatal("remove", err)
	}
	remaining, err := l.observe(ctx, routedLinkOperationV3{kind: "gateway"})
	if err != nil || len(remaining) != 1 || remaining[0].Name != "lo" {
		t.Fatal("namespace not empty after cleanup")
	}
	if err := owned.Close(); err != nil {
		t.Fatal("namespace close", err)
	}
	for _, stage := range []string{"after-detach", "after-remove"} {
		n, err := CreateRoutedGatewayNamespaceV3(ctx, area)
		if err != nil {
			t.Fatal("fault namespace create", err)
		}
		sentinel := errors.New("injected cleanup interruption")
		n.closeStep = func(at string) error {
			if at == stage {
				return sentinel
			}
			return nil
		}
		if err := n.Close(); !errors.Is(err, sentinel) {
			t.Fatal("missing cleanup interruption", stage, err)
		}
		n.closeStep = nil
		if err := n.Close(); err != nil {
			t.Fatal("cleanup retry", stage, err)
		}
	}
	t.Log("real pinned namespaces: two private down children created/read back/removed; parents unchanged")
}

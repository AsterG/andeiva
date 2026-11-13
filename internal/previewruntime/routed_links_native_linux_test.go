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
	if err = l.Enable(ctx); err != nil {
		t.Fatal("enable owned children", err)
	}
	raised, err := l.observe(ctx, routedLinkOperationV3{kind: "gateway"})
	if err != nil || len(raised) != 3 {
		t.Fatal("raised readback", err)
	}
	for _, child := range l.created {
		actual := ownedRoutedLinkV3(raised, child)
		if actual == nil || !containsRoutedLinkFlagV3(actual.Flags, "UP") {
			t.Fatal("created identity not up")
		}
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
	// Exercise the exact manager's retained resources without launching an API
	// or programming L3. The fixture owns this disposable runtime directory.
	folder, err := area.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	if err = folder.Chmod(0755); err != nil {
		t.Fatal(err)
	}
	defer folder.Close()
	node := routedNodeLinksV3{Version: 1, Identity: linkIdentity,
		LAN: routedNodeParentV3{bindings[0].Index, bindings[0].Name, bindings[0].MAC, bindings[0].MTU},
		WAN: routedNodeParentV3{bindings[1].Index, bindings[1].Name, bindings[1].MAC, bindings[1].MTU}}
	managed, err := prepareRoutedManagedNamespaceV3(ctx, area, node, nativeIdentitiesV3)
	if err != nil {
		t.Fatal("managed resources", err)
	}
	if managed.metadata.ValidateRouted() != nil || managed.metadata.SourceNamespace != 0 || managed.metadata.SinkNamespace != 0 {
		t.Fatal("managed metadata scope")
	}
	if err = managed.Close(); err != nil {
		t.Fatal("managed cleanup", err)
	}
	if err = managed.Close(); err != nil {
		t.Fatal("managed cleanup idempotency", err)
	}
	managed, err = prepareRoutedManagedNamespaceV3(ctx, area, node, nativeIdentitiesV3)
	if err != nil {
		t.Fatal("managed sentinel resources", err)
	}
	if err = area.WriteFile("unknown-sentinel", []byte("retain\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = managed.Close(); !errors.Is(err, ErrStorage) {
		t.Fatal("unknown runtime file not reported", err)
	}
	if raw, e := area.ReadFile("unknown-sentinel"); e != nil || string(raw) != "retain\n" {
		t.Fatal("sentinel removed", e)
	}
	if retry, e := prepareRoutedManagedNamespaceV3(ctx, area, node, nativeIdentitiesV3); e == nil || retry != nil {
		t.Fatal("adopted nonempty runtime")
	}
	// The fixture, not the manager, removes its known sentinel after asserting it.
	if err = area.Remove("unknown-sentinel"); err != nil {
		t.Fatal(err)
	}
	remainingEntries, err := area.ReadFile("runtime.json")
	if !os.IsNotExist(err) || len(remainingEntries) != 0 {
		t.Fatal("managed metadata retained", err)
	}
	if err = folder.Chmod(0700); err != nil {
		t.Fatal(err)
	}
	t.Log("real pinned namespaces: two private children created down, raised, read back and removed; parents unchanged")
}

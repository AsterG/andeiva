//go:build linux

package previewruntime

import (
	"context"
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
	host, target := os.NewFile(3, "isolated-parent-namespace"), os.NewFile(4, "isolated-gateway-namespace")
	defer host.Close()
	defer target.Close()
	var hs, ts unix.Stat_t
	if unix.Fstat(3, &hs) != nil || unix.Fstat(4, &ts) != nil || hs.Ino == ts.Ino {
		t.Fatal("namespace pins")
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
	l, err := NewRoutedGatewayLinksV3(ctx, m, host, target, bindings)
	if err != nil {
		t.Fatal("constructor", err)
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
	t.Log("real pinned namespaces: two private down children created/read back/removed; parents unchanged")
}

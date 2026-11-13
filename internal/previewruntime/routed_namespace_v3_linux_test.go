//go:build linux

package previewruntime

import (
	"context"
	"os"
	"testing"
)

func TestRoutedNamespaceV3RejectsUnavailableAuthority(t *testing.T) {
	area, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, call := range []struct {
		ctx  context.Context
		area *os.Root
	}{{nil, area}, {ctx, area}, {context.Background(), nil}} {
		if n, err := CreateRoutedGatewayNamespaceV3(call.ctx, call.area); err == nil || n != nil {
			t.Fatal("invalid authority accepted")
		}
	}
	if os.Geteuid() != 0 {
		if n, err := CreateRoutedGatewayNamespaceV3(context.Background(), area); err == nil || n != nil {
			t.Fatal("capless caller created namespace")
		}
	}
	dir, err := area.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused creation wrote state", err)
	}
}

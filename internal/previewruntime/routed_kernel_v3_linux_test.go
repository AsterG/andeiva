//go:build linux

package previewruntime

import (
	"context"
	"reflect"
	"syscall"
	"testing"

	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/routedactivation"
	"github.com/AsterG/andeiva/internal/routednft"
)

func TestRoutedKernelV3FixedDispatch(t *testing.T) {
	for table, name := range map[routedactivation.Table]string{routedactivation.LegacyTable: firewallnft.TableName, routedactivation.RoutedTable: routednft.TableName, routedactivation.LocalTable: localnft.TableName} {
		cmd, err := routedKernelCommandV3(context.Background(), "observe", table)
		want := []string{"/usr/sbin/nft", "-j", "-n", "-y", "list", "table", "inet", name}
		if err != nil || cmd.Path != want[0] || !reflect.DeepEqual(cmd.Args, want) || cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
			t.Fatal("dispatch differs from the engine table", table, err)
		}
	}
	for _, operation := range []string{"check", "apply", "tables"} {
		cmd, err := routedKernelCommandV3(context.Background(), operation, 0)
		if err != nil || cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
			t.Fatal("kernel subprocess can outlive its helper", operation, err)
		}
	}
	for _, operation := range []string{"", "flush", "list ruleset", "observe;sh"} {
		if cmd, err := routedKernelCommandV3(context.Background(), operation, 0); err == nil || cmd != nil {
			t.Fatal("arbitrary operation accepted")
		}
	}
	if cmd, err := routedKernelCommandV3(context.Background(), "observe", routedactivation.Table(255)); err == nil || cmd != nil {
		t.Fatal("unknown table accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if cmd, err := routedKernelCommandV3(ctx, "apply", 0); err == nil || cmd != nil {
		t.Fatal("cancelled command constructed")
	}
}

func TestRoutedKernelV3RejectsHostOrUnboundExecution(t *testing.T) {
	current, err := namespaceID("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []*routedKernelV3{nil, {}, {namespace: current, host: current}, {namespace: 0, host: current}} {
		if k.Check(context.Background(), []byte(`{"nftables":[]}`)) == nil || k.Apply(context.Background(), nil) == nil {
			t.Fatal("unbound kernel execution accepted")
		}
		if _, _, err := k.Observe(context.Background(), routedactivation.LegacyTable); err == nil {
			t.Fatal("unbound observation accepted")
		}
	}
	if _, err := newRoutedKernelV3(Metadata{}); err == nil {
		t.Fatal("untrusted namespace metadata accepted")
	}
}

func TestRoutedKernelV3RequiresBothLeaderAndLaunchingThread(t *testing.T) {
	k := &routedKernelV3{namespace: 42, host: 11}
	for _, observed := range [][2]uint64{{42, 11}, {11, 42}, {42, 0}, {0, 42}, {11, 11}, {43, 43}} {
		if k.matchesNamespaces(observed[0], observed[1]) {
			t.Fatal("different launching or leader namespace accepted", observed)
		}
	}
	if !k.matchesNamespaces(42, 42) {
		t.Fatal("exact namespace pair rejected")
	}
	k.host = k.namespace
	if k.matchesNamespaces(42, 42) {
		t.Fatal("host namespace accepted")
	}
}

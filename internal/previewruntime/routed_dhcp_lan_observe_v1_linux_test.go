//go:build linux

package previewruntime

import (
	"context"
	"testing"

	"github.com/AsterG/andeiva/internal/dhcpserver"
	"github.com/AsterG/andeiva/internal/routednft"
)

func TestRoutedLANRestoreRequiresPresentServiceV1(t *testing.T) {
	ctx := context.Background()
	l := &routedEmptyListenersV3{kernel: &routedKernelV3{}}
	policy := routednft.LabPolicy()
	policy.DHCPServer = &dhcpserver.Config{Enabled: true}
	if err := l.PrepareRoutedTransition(ctx, &policy, true); err != nil || l.pendingLAN != &policy {
		t.Fatal("provisional target did not record the expected scope", err)
	}
	if err := l.PrepareRoutedTransition(ctx, &policy, false); err != ErrUnavailable || l.pendingLAN != nil {
		t.Fatal("restore accepted a missing server as provisional", err)
	}
}

func TestRoutedLANFailedInstallDoesNotTransferOwnershipV1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l := &routedEmptyListenersV3{kernel: &routedKernelV3{}}
	if installed, err := l.installLANV1(ctx, &routedLANServiceObservationV1{}); installed || err == nil || l.lan != nil {
		t.Fatal("cancelled install acquired ownership", installed, err)
	}
}

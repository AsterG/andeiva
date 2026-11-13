//go:build linux

package previewruntime

import (
	"context"
	"os"
	"testing"
)

func TestRoutedScopeRecoveryV3SlotDoesNotCreateForUnprivilegedCaller(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("nonroot refusal")
	}
	area, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	if slot, err := openScopeRecordSlotV3(area, true); err == nil {
		slot.Close()
		t.Fatal("unprivileged slot created")
	}
	if _, err := area.Stat(routedScopeRecordNameV3); !os.IsNotExist(err) {
		t.Fatal("slot effect", err)
	}
	if _, err := TakeRoutedScopeRecoveryInheritedV3(context.Background()); err == nil {
		t.Fatal("unprivileged inheritance accepted")
	}
	if err := (&RoutedScopeRecoveryV3{}).DropStored(context.Background()); err == nil {
		t.Fatal("unprivileged store removal")
	}
}
func TestRoutedScopeRecoveryV3SlotZeroIsExact(t *testing.T) {
	zero := make([]byte, RoutedScopeRecoveryRecordSizeV3)
	if !scopeRecordZeroV3(zero) {
		t.Fatal("empty reserved slot refused")
	}
	for _, raw := range [][]byte{nil, zero[:len(zero)-1], append(append([]byte{}, zero...), 0)} {
		if scopeRecordZeroV3(raw) {
			t.Fatal("unallocated/truncated slot accepted")
		}
	}
	zero[len(zero)-1] = 1
	if scopeRecordZeroV3(zero) {
		t.Fatal("stale byte discarded")
	}
}

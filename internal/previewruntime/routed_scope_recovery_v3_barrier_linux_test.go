//go:build linux

package previewruntime

import (
	"context"
	"os"
	"testing"
)

func TestRoutedScopeRecoveryV3BarrierRefusesUnprivilegedWithoutCreatingLock(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("capless refusal")
	}
	area, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	ids := Identities{SchemaVersion: 1, APIUID: 62001, APIGID: 62001, HelperUID: 62002, IPCGID: 62003}
	if b, err := openScopeRecoveryBarrierV3(context.Background(), RoutedReaderRootV3{Root: area}, ids); err == nil {
		b.Close()
		t.Fatal("unprivileged lock acquired")
	}
	if _, err := area.Lstat("checkpoint.lock"); !os.IsNotExist(err) {
		t.Fatal("lock was created", err)
	}
}

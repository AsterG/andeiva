//go:build linux

package previewruntime

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestRoutedMigrationChildThreadV3(t *testing.T) {
	if os.Getenv("ANDEIVA_TEST_MIGRATION_THREAD_V3") == "child" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		parent, thread := os.Getppid(), unix.Gettid()
		if armMigrationParentDeathV3(parent) != nil {
			t.Fatal("parent death arm/readback failed")
		}
		for i := 0; i < 1000; i++ {
			runtime.Gosched()
			signal, e := migrationParentDeathSignalV3()
			if unix.Gettid() != thread || os.Getppid() != parent || e != nil || signal != int32(unix.SIGKILL) {
				t.Fatal("configured child thread retired or signal lost", signal, e)
			}
		}
		if armMigrationParentDeathV3(parent+1) == nil || armMigrationParentDeathV3(1) == nil {
			t.Fatal("foreign parent accepted")
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	command := exec.CommandContext(ctx, self, "-test.run=^TestRoutedMigrationChildThreadV3$", "-test.count=1")
	command.Env = append(os.Environ(), "ANDEIVA_TEST_MIGRATION_THREAD_V3=child")
	if output, e := command.CombinedOutput(); e != nil {
		t.Fatalf("child thread regression: %v %s", e, output)
	}
}

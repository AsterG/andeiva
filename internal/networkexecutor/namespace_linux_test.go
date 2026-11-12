package networkexecutor

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestNamespaceRejectsHostAndRegularFile(t *testing.T) {
	// Read-only negative checks: never unshare, enter, or modify any namespace.
	for _, path := range []string{"/proc/self/ns/net", "/proc/1/ns/net", "/dev/null"} {
		t.Run(path, func(t *testing.T) {
			file, err := os.Open(path)
			if err != nil {
				if path == "/proc/1/ns/net" && errors.Is(err, os.ErrPermission) {
					t.Skip("PID 1 namespace is intentionally inaccessible to this unprivileged runner")
				}
				t.Fatal(err)
			}
			if _, err := New(context.Background(), file); !errors.Is(err, ErrScope) {
				t.Fatal(path, err)
			}
			if _, err := file.Stat(); err != nil {
				t.Fatal("constructor closed caller descriptor", err)
			}
			_ = file.Close()
		})
	}
	if _, err := New(context.Background(), nil); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
}

func TestCommandUsesOnlyInheritedNamespaceAndFixedEnvironment(t *testing.T) {
	pin, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	cmd, err := namespaceCommand(context.Background(), pin, operation{kind: "addresses"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != "/usr/bin/nsenter" || !reflect.DeepEqual(cmd.Args[1:], []string{"--net=/proc/self/fd/3", "--", "/usr/bin/ip", "-4", "-j", "address", "show"}) || len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != pin || !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}) || cmd.WaitDelay != 250*time.Millisecond || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatal("command escaped its fixed scope")
	}
	if _, err := namespaceCommand(context.Background(), pin, operation{kind: "arbitrary"}); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
}
func TestNamespaceTypeRejectsOtherNamespace(t *testing.T) {
	f, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := namespaceID(int(f.Fd())); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
}
func TestOutputStorageBound(t *testing.T) {
	b := &limitedBuffer{}
	if n, err := b.Write(make([]byte, maxOutput)); n != maxOutput || err != nil {
		t.Fatal(n, err)
	}
	if n, err := b.Write([]byte("x")); n != 0 || !errors.Is(err, io.ErrShortWrite) || !b.exceeded || len(b.data) != maxOutput {
		t.Fatal(n, err)
	}
}
func TestSupervisorCancellationStopsCommands(t *testing.T) {
	e, _ := fakeExecutor()
	lifetime, cancel := context.WithCancel(context.Background())
	e.lifetime = lifetime
	started := make(chan struct{})
	finished := make(chan error, 1)
	e.run = func(ctx context.Context, _ operation) ([]byte, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() { _, err := e.execute(context.Background(), operation{kind: "addresses"}); finished <- err }()
	<-started
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := e.Apply(context.Background(), fixturePlan()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

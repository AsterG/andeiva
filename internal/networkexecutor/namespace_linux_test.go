package networkexecutor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func ownedIdentityFixture() OwnedNamespaceIdentity {
	return OwnedNamespaceIdentity{UID: 1001, GID: 1002, Namespace: 2, Host: 1, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}
}

func TestOwnedIdentityRequiresCompleteManagerCorrelation(t *testing.T) {
	want := ownedIdentityFixture()
	if !validOwnedIdentity(want) {
		t.Fatal("valid shape rejected")
	}
	for _, mutate := range []func(*OwnedNamespaceIdentity){
		func(v *OwnedNamespaceIdentity) { v.UID = 0 },
		func(v *OwnedNamespaceIdentity) { v.GID = 0 },
		func(v *OwnedNamespaceIdentity) { v.Namespace = v.Host },
		func(v *OwnedNamespaceIdentity) { v.Namespace = 0 },
		func(v *OwnedNamespaceIdentity) { v.Host = 0 },
		func(v *OwnedNamespaceIdentity) { v.RunID = strings.Repeat("A", 32) },
		func(v *OwnedNamespaceIdentity) { v.RunID = "caller" },
		func(v *OwnedNamespaceIdentity) { v.BootID = strings.Replace(v.BootID, "-", "a", 1) },
		func(v *OwnedNamespaceIdentity) { v.BootID = strings.ToUpper(v.BootID) },
	} {
		bad := want
		mutate(&bad)
		if validOwnedIdentity(bad) {
			t.Fatal("invalid identity accepted", bad)
		}
	}
}

func TestOwnedPrivilegesRequireExactIDsAndOnlyNetAdmin(t *testing.T) {
	status := "Uid:\t1001 1001 1001 1001\nGid:\t1002 1002 1002 1002\nNoNewPrivs:\t1\n"
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		status += key + ":\t0000000000001000\n"
	}
	if err := ownedPrivileges([]byte(status), 1001, 1002); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(status, "1001", "0", 1),
		strings.Replace(status, "1002", "1003", 1),
		strings.Replace(status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1),
		strings.Replace(status, "0000000000001000", "0000000000201000", 1),
		strings.Replace(status, "0000000000001000", "0000000000000000", 1),
		status + "CapEff:\t0000000000001000\n",
		strings.Replace(status, "CapAmb:\t0000000000001000\n", "", 1),
		strings.Replace(status, "1001 1001 1001 1001", "1001 1001 1001", 1),
	} {
		if !errors.Is(ownedPrivileges([]byte(bad), 1001, 1002), ErrScope) {
			t.Fatal("untrusted privileges accepted")
		}
	}
	if ownedPrivileges([]byte(status), 0, 1002) == nil || ownedPrivileges([]byte(status), 1001, 0) == nil {
		t.Fatal("root identity accepted")
	}
}

func TestOwnedCommandDirectFixedIPWithoutInheritedPins(t *testing.T) {
	cmd, err := ownedNamespaceCommand(context.Background(), operation{kind: "addresses"})
	if err != nil || cmd.Path != "/usr/bin/ip" || !reflect.DeepEqual(cmd.Args[1:], []string{"-4", "-j", "address", "show"}) || len(cmd.ExtraFiles) != 0 || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL || cmd.WaitDelay != 250*time.Millisecond || len(cmd.Env) != 3 {
		t.Fatal("direct command escaped scope", err)
	}
	if _, err := ownedNamespaceCommand(nil, operation{kind: "addresses"}); !errors.Is(err, ErrScope) {
		t.Fatal("nil context accepted", err)
	}
	if _, err := ownedNamespaceCommand(context.Background(), operation{kind: "shell"}); !errors.Is(err, ErrScope) {
		t.Fatal("arbitrary operation accepted", err)
	}
}

func TestOwnedConstructorRejectsHostForeignAndReplacedDescriptors(t *testing.T) {
	self, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	id, err := namespaceID(int(self.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	want := ownedIdentityFixture()
	want.Namespace = id
	want.Host = id + 1
	pin, _, err := pinNamespace(self)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	replacement, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err := unix.Dup3(int(replacement.Fd()), int(pin.Fd()), unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnedNamespace(pin, self, want); !errors.Is(err, ErrScope) {
		t.Fatal("replaced retained descriptor accepted", err)
	}
	for _, path := range []string{"/proc/self/ns/net", "/proc/self/ns/mnt", "/dev/null"} {
		foreign, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if e, err := NewInOwnedNamespace(context.Background(), self, foreign, want); !errors.Is(err, ErrScope) || e != nil {
			t.Fatal("foreign/host descriptor accepted", err)
		}
		if _, err := foreign.Stat(); err != nil {
			t.Fatal("caller descriptor closed", err)
		}
		_ = foreign.Close()
	}
	closed, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	if err := verifyOwnedNamespace(closed, self, want); !errors.Is(err, ErrScope) {
		t.Fatal("closed/replaced pin accepted", err)
	}
	if e, err := NewInOwnedNamespace(nil, self, self, want); e != nil || !errors.Is(err, ErrScope) {
		t.Fatal("nil lifetime accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e, err := NewInOwnedNamespace(ctx, self, self, want); e != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled supervisor accepted", err)
	}
}

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

func TestSelfNetworkNamespaceTypeReadOnly(t *testing.T) {
	file, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	id, err := namespaceID(int(file.Fd()))
	if err != nil || id == 0 {
		t.Fatal("current network namespace did not pass nsfs/NS_GET_NSTYPE validation", id, err)
	}
}

func TestNamespacePinOutlivesCallerDescriptor(t *testing.T) {
	source, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	pin, id, err := pinNamespace(source)
	if err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	defer pin.Close()
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := namespaceID(int(pin.Fd()))
	if err != nil || got != id {
		t.Fatal("caller close invalidated owned namespace pin", got, err)
	}
}

func TestPinRejectsRegularForeignTypeAndClosedDescriptors(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "not-a-namespace")
	if err := os.WriteFile(regular, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{regular, "/dev/null", "/proc/self/ns/mnt"} {
		t.Run(path, func(t *testing.T) {
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if pin, _, err := pinNamespace(file); !errors.Is(err, ErrScope) || pin != nil {
				if pin != nil {
					_ = pin.Close()
				}
				t.Fatal("foreign descriptor accepted", err)
			}
			if _, err := file.Stat(); err != nil {
				t.Fatal("caller descriptor closed on rejection", err)
			}
		})
	}
	file, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if pin, _, err := pinNamespace(file); !errors.Is(err, ErrScope) || pin != nil {
		t.Fatal("closed descriptor accepted", err)
	}
}

func TestHostBindingRequiresCurrentHostAndDistinctTarget(t *testing.T) {
	if !validNamespaceBinding(2, 1, 1) {
		t.Fatal("trusted host/current binding rejected")
	}
	for _, ids := range [][3]uint64{{1, 1, 1}, {2, 3, 1}, {1, 2, 1}, {0, 1, 1}, {2, 0, 0}, {2, 1, 0}} {
		if validNamespaceBinding(ids[0], ids[1], ids[2]) {
			t.Fatal("self or foreign host accepted", ids)
		}
	}
}

func TestNewWithHostRejectsSelfAndKeepsCallerDescriptors(t *testing.T) {
	self, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	if executor, err := NewWithHost(context.Background(), self, self); !errors.Is(err, ErrScope) || executor != nil {
		if executor != nil {
			_ = executor.Close()
		}
		t.Fatal("target host accepted", err)
	}
	if _, err := self.Stat(); err != nil {
		t.Fatal("constructor closed caller host descriptor", err)
	}
	for _, input := range []struct {
		ctx          context.Context
		target, host *os.File
	}{{nil, self, self}, {context.Background(), nil, self}, {context.Background(), self, nil}} {
		if executor, err := NewWithHost(input.ctx, input.target, input.host); !errors.Is(err, ErrScope) || executor != nil {
			t.Fatal("invalid host constructor accepted", err)
		}
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

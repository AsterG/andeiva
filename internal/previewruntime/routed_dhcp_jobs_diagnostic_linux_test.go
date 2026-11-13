//go:build linux && andeiva_native_dhcp_diagnostics

package previewruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type nativeDHCPDiagnosticCaptureV4 struct {
	root       *os.Root
	pin        *os.File
	data       []byte
	err        error
	stop, done chan struct{}
}

func pinNativeDHCPDiagnosticV4(owner *RoutedDHCPOwnerV3, m Metadata) (*nativeDHCPDiagnosticCaptureV4, error) {
	if owner == nil || os.Getuid() != 0 || os.Geteuid() != 0 || routedDHCPOwnerCgroupV3() != nil {
		return nil, ErrIdentity
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	b := owner.deferred
	if owner.closed || owner.profile != 4 || !routedDHCPDeferredBindingValidV4(b) || b.Owner.RunID != m.RunID || b.Owner.BootID != m.BootID || b.Owner.Namespace != m.GatewayNamespace || !routedDHCPOwnerNamespaceV3(owner.mount, unix.CLONE_NEWNS, b.MountNamespace) || !routedDHCPOwnerPIDFDAliveV3(owner.producerFD, int(b.Owner.PID)) {
		return nil, ErrIdentity
	}
	pid := int(b.Owner.PID)
	pin, start, err := routedDHCPOwnerPinV3(pid, os.Getpid(), b.Owner.Namespace, b.MountNamespace)
	if err != nil {
		return nil, err
	}
	fail := func() (*nativeDHCPDiagnosticCaptureV4, error) { _ = pin.Close(); return nil, ErrIdentity }
	if start != b.Owner.StartTicks {
		return fail()
	}
	group, err := routedDHCPOwnerReadV3(fmt.Sprintf("/proc/%d/cgroup", pid), 4096)
	if err != nil || string(group) != "0::"+routedSupervisorCgroupV3+"\n" {
		return fail()
	}
	// The PID comes only from the authenticated root-owned constructor handle.
	// Retain the directory capability now; never reopen /proc after teardown.
	root, err := os.OpenRoot(fmt.Sprintf("/proc/%d/root/run/andeiva-dhcp", pid))
	if err != nil {
		return fail()
	}
	end, parent, err := routedDHCPOwnerProcessV3(pid)
	mount, mountErr := namespaceID(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil || mountErr != nil || mount != b.MountNamespace || end != start || parent != os.Getpid() || !routedDHCPOwnerPIDFDAliveV3(pin, pid) {
		_ = root.Close()
		return fail()
	}
	return &nativeDHCPDiagnosticCaptureV4{root: root, pin: pin, stop: make(chan struct{}), done: make(chan struct{})}, nil
}

func readNativeDHCPDiagnosticV4(root *os.Root, uid uint32) ([]byte, error) {
	parent, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	dir, err := unix.Openat(int(parent.Fd()), "native-diagnostics", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	var state unix.Stat_t
	if unix.Fstat(dir, &state) != nil || state.Mode&unix.S_IFMT != unix.S_IFDIR || state.Mode&07777 != 0700 || state.Uid != uid {
		return nil, ErrIdentity
	}
	fd, err := unix.Openat(dir, "events.jsonl", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "native-dhcp-diagnostic-reader")
	defer f.Close()
	if unix.Fstat(int(f.Fd()), &state) != nil || state.Mode&unix.S_IFMT != unix.S_IFREG || state.Mode&07777 != 0600 || state.Uid != uid || state.Nlink != 1 || state.Size < 0 || state.Size > 64<<10 {
		return nil, ErrIdentity
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return nil, ErrIdentity
	}
	return data, nil
}

func (c *nativeDHCPDiagnosticCaptureV4) run(ctx context.Context) {
	defer close(c.done)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	read := func() {
		data, err := readNativeDHCPDiagnosticV4(c.root, 0)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			c.err = err
			return
		}
		c.data = data
	}
	for {
		select {
		case <-ctx.Done():
			read()
			return
		case <-ticker.C:
			read()
		case <-c.stop:
			read()
			return
		}
	}
}

func nativeDHCPJobsCollectV4(t *testing.T, ctx context.Context, m Metadata) func() {
	t.Helper()
	var capture *nativeDHCPDiagnosticCaptureV4
	var failure error
	unregister, err := captureNativeDHCPDiagnosticV4(func(owner *RoutedDHCPOwnerV3) {
		if ctx.Err() != nil || capture != nil || failure != nil {
			failure = ErrIdentity
			return
		}
		capture, failure = pinNativeDHCPDiagnosticV4(owner, m)
		if failure == nil {
			go capture.run(ctx)
		}
	})
	if err != nil {
		t.Fatal("native diagnostic registration", err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			unregister() // Waits for a constructor callback before reading its result.
			if capture != nil {
				close(capture.stop)
				<-capture.done
				_ = capture.root.Close()
				_ = capture.pin.Close()
				if capture.err != nil {
					failure = capture.err
				}
				for _, line := range strings.Split(strings.TrimSpace(string(capture.data)), "\n") {
					if line != "" {
						t.Logf("ANDEIVA_NATIVE_DHCP_OWNER %s", line)
					}
				}
			}
			if failure != nil || capture == nil || len(capture.data) == 0 {
				t.Errorf("native diagnostic unavailable: %v", failure)
			}
		})
	}
}

func TestNativeDHCPDiagnosticRegistryLifetime(t *testing.T) {
	calls := 0
	stop, err := captureNativeDHCPDiagnosticV4(func(*RoutedDHCPOwnerV3) { calls++ })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if other, err := captureNativeDHCPDiagnosticV4(func(*RoutedDHCPOwnerV3) {}); err == nil || other != nil {
		t.Fatal("second consumer replaced fixture")
	}
	registerNativeDHCPDiagnosticV4(nil)
	stop()
	stop()
	registerNativeDHCPDiagnosticV4(nil)
	if calls != 1 {
		t.Fatal("registration survived close", calls)
	}
	if capture, err := pinNativeDHCPDiagnosticV4(nil, Metadata{}); err == nil || capture != nil {
		t.Fatal("untrusted handle accepted")
	}
	if other, err := captureNativeDHCPDiagnosticV4(nil); err == nil || other != nil {
		t.Fatal("nil consumer accepted")
	}
}

func TestNativeDHCPDiagnosticReaderRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"valid", "directory_mode", "file_mode", "symlink", "hardlink", "oversize", "wrong_owner"} {
		t.Run(kind, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err = root.Mkdir("native-diagnostics", 0700); err != nil {
				t.Fatal(err)
			}
			if err = root.WriteFile("native-diagnostics/events.jsonl", []byte("{\"stage\":\"started\"}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			info, err := root.Stat("native-diagnostics/events.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			uid := info.Sys().(*syscall.Stat_t).Uid
			switch kind {
			case "directory_mode":
				err = root.Chmod("native-diagnostics", 0755)
			case "file_mode":
				err = root.Chmod("native-diagnostics/events.jsonl", 0644)
			case "symlink":
				err = root.Rename("native-diagnostics/events.jsonl", "native-diagnostics/other")
				if err == nil {
					err = root.Symlink("other", "native-diagnostics/events.jsonl")
				}
			case "hardlink":
				err = root.Link("native-diagnostics/events.jsonl", "native-diagnostics/other")
			case "oversize":
				err = root.WriteFile("native-diagnostics/events.jsonl", make([]byte, (64<<10)+1), 0600)
			case "wrong_owner":
				uid ^= 1
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := readNativeDHCPDiagnosticV4(root, uid)
			if kind == "valid" {
				if err != nil || len(data) == 0 {
					t.Fatal(err)
				}
			} else if err == nil || len(data) != 0 {
				t.Fatal("unsafe file accepted")
			}
		})
	}
}

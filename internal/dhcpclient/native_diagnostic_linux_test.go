//go:build linux && andeiva_native_dhcp_diagnostics

package dhcpclient

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func diagnosticDirectory(t *testing.T) (string, int, uint32) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	return path, fd, st.Uid
}

func TestNativeDiagnosticPermissionsAndExclusive(t *testing.T) {
	for _, kind := range []string{"writable_parent", "wrong_owner", "symlink", "existing_directory"} {
		t.Run(kind, func(t *testing.T) {
			path, fd, uid := diagnosticDirectory(t)
			switch kind {
			case "writable_parent":
				if err := os.Chmod(path, 0770); err != nil {
					t.Fatal(err)
				}
			case "wrong_owner":
				uid ^= 1
			case "symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(path, "native-diagnostics")); err != nil {
					t.Fatal(err)
				}
			case "existing_directory":
				if err := os.Mkdir(filepath.Join(path, "native-diagnostics"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if d, err := openClientDiagnosticAt(fd, uid); err == nil || d != nil {
				t.Fatal("unsafe diagnostic directory accepted")
			}
		})
	}
	path, fd, uid := diagnosticDirectory(t)
	d, err := openClientDiagnosticAt(fd, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	info, err := os.Stat(filepath.Join(path, "native-diagnostics", "events.jsonl"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("diagnostic not private", err)
	}
	if other, err := openClientDiagnosticAt(fd, uid); err == nil || other != nil {
		t.Fatal("existing diagnostic replaced")
	}
}

func TestNativeDiagnosticBoundAndRedaction(t *testing.T) {
	path, fd, uid := diagnosticDirectory(t)
	d, err := openClientDiagnosticAt(fd, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	w := d.stderr()
	private := []byte("wan0: offered 198.18.1.10 from private-host.example option=do-not-log\n")
	if n, err := w.Write(private); err != nil || n != len(private) {
		t.Fatal("stderr rejected", err)
	}
	for i := 0; i < 4000; i++ {
		d.event("event", "CARRIER", 0)
	}
	data, err := os.ReadFile(filepath.Join(path, "native-diagnostics", "events.jsonl"))
	if err != nil || len(data) > clientDiagnosticLimit || !bytes.HasSuffix(data, []byte("{\"stage\":\"truncated\"}\n")) || bytes.Count(data, []byte("\"truncated\"")) != 1 {
		t.Fatal("diagnostic limit not explicit", len(data), err)
	}
	if !bytes.Contains(data, []byte("\"detail\":\"offer\"")) || strings.Contains(string(data), "198.18") || strings.Contains(string(data), "private-host") || strings.Contains(string(data), "do-not-log") {
		t.Fatal("raw stderr escaped")
	}
	if n, err := w.Write(bytes.Repeat([]byte("x"), 1<<20)); err != nil || n != 1<<20 {
		t.Fatal("truncated diagnostic blocked engine", err)
	}
	after, err := os.ReadFile(filepath.Join(path, "native-diagnostics", "events.jsonl"))
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("write after truncation", err)
	}
	d.close()
	if n, err := w.Write(private); err != nil || n != len(private) {
		t.Fatal("closed diagnostic blocked engine", err)
	}
}

func TestNativeDiagnosticValidatedLeaseSeconds(t *testing.T) {
	path, fd, uid := diagnosticDirectory(t)
	d, err := openClientDiagnosticAt(fd, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	event, err := HookEvent(goodEnv(), 1)
	if err != nil {
		t.Fatal(err)
	}
	d.leaseEvent(event)
	file := filepath.Join(path, "native-diagnostics", "events.jsonl")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"lease_seconds":120`)) || !bytes.Contains(data, []byte(`"detail":"BOUND"`)) || bytes.Contains(data, []byte(event.Address)) || bytes.Contains(data, []byte(event.Gateway)) {
		t.Fatal("missing validated duration or raw option escaped", string(data))
	}
	for _, seconds := range []uint32{0, 9, 604801, ^uint32(0)} {
		event.Seconds = seconds
		d.leaseEvent(event)
	}
	after, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("invalid duration emitted", err)
	}
	event, err = HookEvent(replace(goodEnv(), "reason", "EXPIRE"), 2)
	if err != nil {
		t.Fatal(err)
	}
	d.leaseEvent(event)
	after, err = os.ReadFile(file)
	if err != nil || !bytes.Contains(after, []byte(`"detail":"EXPIRE"`)) || bytes.Count(after, []byte(`"lease_seconds"`)) != 1 {
		t.Fatal("expiry invented lease duration", err)
	}
}

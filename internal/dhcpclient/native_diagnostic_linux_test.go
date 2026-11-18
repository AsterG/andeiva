//go:build linux && andeiva_native_dhcp_diagnostics

package dhcpclient

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeDiagnosticDebugArgumentsFixedAndIndependent(t *testing.T) {
	var d *clientDiagnostic
	args := d.debugArguments()
	if !reflect.DeepEqual(args, []string{"-d"}) {
		t.Fatal("native verbosity not fixed", args)
	}
	args[0] = "caller-mutated"
	if !reflect.DeepEqual(d.debugArguments(), []string{"-d"}) {
		t.Fatal("native flags share mutable state")
	}
}

func TestNativeDiagnosticUpstreamStateClassesRemainRedacted(t *testing.T) {
	path, fd, uid := diagnosticDirectory(t)
	d, err := openClientDiagnosticAt(fd, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	w := d.stderr()
	for _, tc := range []struct{ line, code string }{
		{"received SIGUSR1, renewing", "renew_signal"},
		{"wan0: renewing lease of 203.0.113.77", "renew_request"},
		{"wan0: sending REQUEST (xid 0x12345678), next in 4.2 seconds", "request_send"},
		{"wan0: failed to renew DHCP, rebinding", "renew_rebind"},
		{"wan0: rebinding lease of 203.0.113.77", "reboot_request"},
		{"wan0: probing address 203.0.113.77/24", "address_probe"},
		{"wan0: waiting for DAD on 203.0.113.77", "address_probe"},
		{"wan0: Duplicate address detected", "address_conflict"},
		{"wan0: declined duplicate address", "address_conflict"},
		{"wan0: checksum failure from 203.0.113.1", "rx_checksum"},
		{"wan0: wrong xid 0x12345678 (expecting 0x87654321) from 203.0.113.1", "rx_wrong_xid"},
		{"wan0: xid 0x12345678 is for hwaddr 02:00:00:00:00:ff", "rx_wrong_hwaddr"},
		{"wan0: bound, ignoring", "rx_bound_ignored"},
		{"wan0: probing, ignoring", "rx_probe_ignored"},
		{"wan0: reject DHCP", "rx_rejected_option"},
		{"wan0: reject NAK", "rx_rejected_nak"},
		{"wan0: reject invalid address", "rx_invalid_address"},
		{"ps_inet_openbootp: No such file or directory", "udp_open_error"},
		{"dhcp_openudp: Address already in use", "udp_open_error"},
		{"ps_inet_startcb: dhcp_open: Permission denied", "udp_open_error"},
		{"dhcp_handleifa: No such file or directory", "address_socket_error"},
		{"dhcp_bind: Invalid argument", "bind_error"},
		{"wan0: dhcp_sendudp: Operation not permitted", "udp_send_error"},
		{"ps_inet_recvbootp: Invalid argument", "udp_receive_error"},
		{"wan0: DHCP BPF validation failure", "bpf_validation"},
		{"wan0: bpf_send: No buffer space available", "bpf_send_error"},
		{"wan0: Permission denied", "permission"},
		{"private unknown state 203.0.113.77 xid0x12345678", "unclassified"},
	} {
		line := tc.line + " private-host.example /private/path option=never-log\n"
		if got := clientDiagnosticClass(line); got != tc.code {
			t.Fatal("wrong specific/generic precedence", tc.line, got, tc.code)
		}
		// Fragmented engine writes must classify the complete line once.
		for _, fragment := range []string{line[:len(line)/2], line[len(line)/2:]} {
			if n, e := w.Write([]byte(fragment)); e != nil || n != len(fragment) {
				t.Fatal(e, n)
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(path, "native-diagnostics", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > clientDiagnosticLimit || strings.Count(string(raw), "\n") != 28 {
		t.Fatal("unbounded or split diagnostic", len(raw))
	}
	for _, secret := range []string{"203.0.113", "0x12345678", "02:00:00", "private-host", "/private/path", "never-log"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("raw engine data escaped classifier", secret)
		}
	}
}

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

//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpkea"
	"golang.org/x/sys/unix"
)

func TestRoutedDHCPServerCommandV1(t *testing.T) {
	for _, check := range []bool{false, true} {
		cmd := routedDHCPServerCommandV1(62020, 62021, check)
		want := []string{"/usr/bin/setpriv", "--reuid=62020", "--regid=62021", "--clear-groups", "--bounding-set=-all,+net_bind_service,+net_raw", "--inh-caps=-all,+net_bind_service,+net_raw", "--ambient-caps=-all,+net_bind_service,+net_raw", "--no-new-privs", "--pdeathsig=SIGKILL", "--apparmor-profile=kea-dhcp4", "--", "/usr/sbin/kea-dhcp4", "-c", "/etc/kea/kea-dhcp4.conf"}
		if check {
			want[4], want[5], want[6], want[9] = "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--apparmor-profile=kea-lfc"
			want = append(want[:11], "/usr/sbin/kea-lfc", "-4", "-d", "-p", "/var/lib/kea/kea-leases4.csv.pid", "-x", "/var/lib/kea/kea-leases4.csv.2", "-i", "/var/lib/kea/kea-leases4.csv.1", "-o", "/var/lib/kea/kea-leases4.csv.output", "-f", "/var/lib/kea/kea-leases4.csv.completed", "-c", "/etc/kea/kea-dhcp4.conf")
		}
		if !reflect.DeepEqual(cmd.Args, want) || cmd.Path != want[0] || len(cmd.ExtraFiles) != 0 || cmd.SysProcAttr.Pdeathsig != unix.SIGKILL || !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}) {
			t.Fatal("engine launch boundary changed", cmd.Args)
		}
		if !check && (cmd.Stdout != os.Stdout || cmd.Stderr != os.Stderr) {
			t.Fatal("serving output must be direct fixed files")
		}
	}
}

func TestRoutedDHCPServerRefusesUnassembledRoleV1(t *testing.T) {
	if err := RunRoutedDHCPServerComponentV1(nil, RoutedDHCPServerResourcesV1{}); err != ErrIdentity {
		t.Fatal(err)
	}
	if err := RunRoutedDHCPServerComponentV1(context.Background(), RoutedDHCPServerResourcesV1{}); err != ErrIdentity {
		t.Fatal(err)
	}
	if err := routedDHCPServerScopeV1(RoutedDHCPServerResourcesV1{}); err != ErrIdentity {
		t.Fatal(err)
	}
	if err := routedDHCPServerConfigFileV1(nil, nil, 1); err != ErrIdentity {
		t.Fatal(err)
	}
}

func routedDHCPServerTestCommandV1(t *testing.T, mode string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestRoutedDHCPServerChildV1$", "-test.count=1")
	cmd.Env = []string{"ANDEIVA_DHCP_SERVER_TEST_CHILD=" + mode}
	return cmd
}

func TestRoutedDHCPServerChildV1(t *testing.T) {
	switch os.Getenv("ANDEIVA_DHCP_SERVER_TEST_CHILD") {
	case "":
		t.Skip("subprocess only")
	case "exit":
		return
	case "wait":
		ctx, stop := signal.NotifyContext(context.Background(), unix.SIGTERM)
		defer stop()
		_, _ = os.Stdout.Write([]byte("ready\n"))
		<-ctx.Done()
	case "blocked-output":
		if err := unix.SetNonblock(1, false); err != nil {
			t.Fatal(err)
		}
		if _, err := unix.Write(2, []byte("writing\n")); err != nil {
			t.Fatal(err)
		}
		if _, err := unix.Write(1, []byte("blocked")); err != nil {
			t.Fatal(err)
		}
		_, _ = unix.Write(2, []byte("completed\n"))
	case "umask":
		unix.Umask(0077)
		uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
		if gid == 0 {
			t.Skip("requires unprivileged group")
		}
		root := t.TempDir()
		parent := filepath.Join(root, "lock")
		if err := routedDHCPServerDirectoryV1(parent, uid, gid, 0750); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(parent)
		if err != nil || info.Mode() != os.ModeDir|0750 {
			t.Fatal("umask removed group traversal", info, err)
		}
		child := filepath.Join(parent, "kea")
		if err := routedDHCPServerDirectoryV1(child, uid, gid, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(child, "logger_lockfile"), []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown child mode")
	}
}

func TestRoutedDHCPServerUmaskTraversalV1(t *testing.T) {
	cmd := routedDHCPServerTestCommandV1(t, "umask")
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
}

func TestRoutedDHCPServerAtomicPIDFDV1(t *testing.T) {
	old, done, err := routedDHCPServerStartV1(routedDHCPServerTestCommandV1(t, "exit"))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(old)
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("early child did not exit")
	}
	// Retain the exited child's kernel handle while another process exists.
	cmd := routedDHCPServerTestCommandV1(t, "wait")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	cmd.Stdout = writer
	current, currentDone, err := routedDHCPServerStartV1(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(current)
	defer func() { _ = unix.PidfdSendSignal(current, unix.SIGKILL, nil, 0); <-currentDone }()
	if reader.SetReadDeadline(time.Now().Add(5*time.Second)) != nil {
		t.Fatal("pipe deadline")
	}
	ready := make([]byte, 6)
	if _, err = io.ReadFull(reader, ready); err != nil || string(ready) != "ready\n" {
		t.Fatal("child readiness", err)
	}
	if err = unix.PidfdSendSignal(old, unix.SIGTERM, nil, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatal("old pidfd did not reject signal", err)
	}
	poll := []unix.PollFd{{Fd: int32(current), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
		t.Fatal("unrelated process affected", n, err)
	}
}

func TestRoutedDHCPServerCancellationV1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := routedDHCPServerTestCommandV1(t, "wait")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	cmd.Stdout = writer
	done := make(chan error, 1)
	go func() { done <- routedDHCPServerWaitV1(ctx, cmd, false) }()
	defer cancel()
	_ = reader.SetReadDeadline(time.Now().Add(5 * time.Second))
	ready := make([]byte, 6)
	if _, err = io.ReadFull(reader, ready); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("cancellation did not reap")
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
		t.Fatal("missing completed Wait")
	}
	pre, cancelPre := context.WithCancel(context.Background())
	cancelPre()
	unused := routedDHCPServerTestCommandV1(t, "exit")
	if routedDHCPServerWaitV1(pre, unused, true) == nil || unused.Process != nil {
		t.Fatal("cancelled context spawned")
	}
}

func TestRoutedDHCPServerBlockedOutputCancellationV1(t *testing.T) {
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()
	defer outW.Close()
	outFD := int(outW.Fd())
	capacity, err := unix.FcntlInt(uintptr(outFD), unix.F_GETPIPE_SZ, 0)
	if err != nil || capacity <= 0 {
		t.Fatal("pipe capacity", err)
	}
	if err = unix.SetNonblock(outFD, true); err != nil {
		t.Fatal(err)
	}
	filled := 0
	for {
		n, e := unix.Write(outFD, make([]byte, 4096))
		if n > 0 {
			filled += n
		}
		if errors.Is(e, unix.EAGAIN) {
			break
		}
		if e != nil || n == 0 {
			t.Fatal("fill output pipe", e)
		}
	}
	if filled != capacity {
		t.Fatal("pipe not full", filled, capacity)
	}
	if err = unix.SetNonblock(outFD, false); err != nil {
		t.Fatal(err)
	}
	controlR, controlW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer controlR.Close()
	defer controlW.Close()
	cmd := routedDHCPServerTestCommandV1(t, "blocked-output")
	cmd.Stdout, cmd.Stderr = outW, controlW // Files, no exec-owned output copier.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- routedDHCPServerWaitV1(ctx, cmd, false) }()
	if err = controlR.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ready := make([]byte, 8)
	if _, err = io.ReadFull(controlR, ready); err != nil || string(ready) != "writing\n" {
		t.Fatal("child write attempt", err)
	}
	if err = controlR.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err = controlR.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("child unexpectedly completed blocked write", err)
	}
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Wait blocked on undrained stdout")
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Sys().(syscall.WaitStatus).Signaled() {
		t.Fatal("blocked child not killed and reaped")
	}
	// Do not read stdout, even after cancellation: its original full buffer
	// remains intact, proving completion did not depend on draining the sink.
	remaining, err := unix.IoctlGetInt(int(outR.Fd()), unix.TIOCINQ)
	if err != nil || remaining != filled {
		t.Fatal("stdout was drained", remaining, filled, err)
	}
}

func TestRoutedDHCPServerLeaseDiagnosticsV1(t *testing.T) {
	valid := "INFO [kea-lfc] LFC_READ_STATS Leases: 12, attempts: 13, errors: 0.\nINFO [kea-lfc] LFC_WRITE_STATS Leases: 10, attempts: 10, errors: 0.\nINFO [kea-lfc] LFC_TERMINATE LFC finished processing\n"
	for _, text := range []string{"", "LFC_TERMINATE", valid + "ERROR [kea-dhcpsrv] DHCPSRV_MEMFILE_LEASE_LOAD_ROW_ERROR corrupted row", valid + "WARN lease subnet mismatch", valid + "FATAL load failed", strings.Replace(valid, "errors: 0", "errors: 1", 1), valid + valid, strings.Replace(valid, "Leases: 12", "Leases: 18446744073709551616", 1)} {
		b := &routedDHCPServerLogV1{}
		if _, err := b.Write([]byte(text)); err != nil || b.clean() {
			t.Fatal("diagnostic admitted", err)
		}
	}
	b := &routedDHCPServerLogV1{}
	_, _ = b.Write([]byte(valid))
	if !b.clean() {
		t.Fatal("complete zero-error check refused")
	}
	before := len(b.data)
	if _, err := b.Write(bytes.Repeat([]byte{'x'}, dhcpkea.MaxArtifactBytes+1)); err == nil || b.clean() || len(b.data) != before {
		t.Fatal("unbounded log")
	}
}

func TestRoutedDHCPServerLeaseFilesV1(t *testing.T) {
	if os.Getuid() == 0 || os.Getgid() == 0 {
		t.Skip("unprivileged file-ownership test")
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	check := func(want bool, budget int64) {
		t.Helper()
		err := routedDHCPServerLeasesV1(f, uid, gid, budget)
		if (err == nil) != want {
			t.Fatalf("allowed=%v error=%v", want, err)
		}
	}
	check(true, 1024)
	check(false, 0)
	if routedDHCPServerLeasesV1(f, uid+1, gid, 1024) == nil {
		t.Fatal("foreign owner")
	}
	lease := filepath.Join(dir, "kea-leases4.csv")
	if err := os.WriteFile(lease, []byte("Kea will validate content"), 0600); err != nil {
		t.Fatal(err)
	}
	check(true, 1024) // Filesystem validation makes no CSV-integrity claim.
	check(false, 1)
	if err := os.Chmod(lease, 0644); err != nil {
		t.Fatal(err)
	}
	check(false, 1024)
	if err := os.Chmod(lease, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "kea-leases4.csv.1")
	if err := os.Link(lease, alias); err != nil {
		t.Fatal(err)
	}
	check(false, 1024)
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(lease, alias); err != nil {
		t.Fatal(err)
	}
	check(false, 1024)
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(alias, 0600); err != nil {
		t.Fatal(err)
	}
	check(false, 1024)
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	pid := filepath.Join(dir, "kea-leases4.csv.pid")
	if err := os.WriteFile(pid, []byte("123"), 0600); err != nil {
		t.Fatal(err)
	}
	check(false, 1024)
	for _, name := range []string{"../kea-leases4.csv", "kea-leases4.csv.pid", "kea-leases6.csv", "kea-leases4.csv.3", "unknown", strings.Repeat("x", 512)} {
		if routedDHCPServerLeaseNameV1(name) {
			t.Fatal(name)
		}
	}
}

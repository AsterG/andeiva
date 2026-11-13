//go:build linux

package previewruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const scopeProbeUnitV3 = "andeiva-cgroup-retirement-probe.service"
const scopeProbeGroupV3 = "/system.slice/" + scopeProbeUnitV3
const scopeProbePathV3 = "/sys/fs/cgroup" + scopeProbeGroupV3

type scopeProbeOperationV3 uint8

const (
	scopeProbeShowV3 scopeProbeOperationV3 = iota
	scopeProbeStartV3
	scopeProbeStopV3
)

type scopeProbeStateV3 struct{ load, invocation, group, pid, description string }

func scopeProbeCommandV3(parent context.Context, op scopeProbeOperationV3, nonce string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch op {
	case scopeProbeShowV3:
		cmd = exec.CommandContext(ctx, "/usr/bin/systemctl", "--no-pager", "show", "--property=LoadState", "--property=InvocationID", "--property=ControlGroup", "--property=MainPID", "--property=Description", scopeProbeUnitV3)
	case scopeProbeStartV3:
		if !validHex(nonce, 16) {
			return nil, ErrIdentity
		}
		cmd = exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--unit="+scopeProbeUnitV3, "--description=ANDEIVA cgroup retirement probe "+nonce, "--collect", "--property=Type=exec", "--property=KillMode=control-group", "--property=RuntimeMaxSec=30s", "--property=TimeoutStopSec=2s", "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=", "/usr/bin/sleep", "30")
	case scopeProbeStopV3:
		cmd = exec.CommandContext(ctx, "/usr/bin/systemctl", "--no-pager", "stop", scopeProbeUnitV3)
	default:
		return nil, ErrIdentity
	}
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C", "SYSTEMD_COLORS=0"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 200 * time.Millisecond
	var output scopeRecoveryOutputV3
	cmd.Stdout = &output
	runtime.LockOSThread()
	err := cmd.Run()
	runtime.UnlockOSThread()
	if err != nil || ctx.Err() != nil {
		return output.Bytes(), errors.Join(err, ctx.Err())
	}
	return output.Bytes(), nil
}
func scopeProbeStateReadV3(ctx context.Context) (scopeProbeStateV3, error) {
	var s scopeProbeStateV3
	raw, err := scopeProbeCommandV3(ctx, scopeProbeShowV3, "")
	if err != nil || len(raw) > 4096 {
		return s, errors.Join(err, ErrIdentity)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return s, ErrIdentity
		}
		seen[key] = true
		switch key {
		case "LoadState":
			s.load = value
		case "InvocationID":
			s.invocation = value
		case "ControlGroup":
			s.group = value
		case "MainPID":
			s.pid = value
		case "Description":
			s.description = value
		default:
			return s, ErrIdentity
		}
	}
	if len(seen) != 5 {
		return s, ErrIdentity
	}
	return s, nil
}
func scopeProbeWaitAbsentV3(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		s, err := scopeProbeStateReadV3(ctx)
		if err != nil {
			t.Fatal("probe absence readback", err)
		}
		if s.load == "not-found" {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("probe did not unload")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// Stop only the invocation this test created. Empty/mismatching identity is
// retained for operator inspection; a fixed unit name alone never authorizes stop.
func scopeProbeStopOwnedV3(invocation, nonce string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := scopeProbeStateReadV3(ctx)
	if err != nil {
		return err
	}
	if s.load == "not-found" {
		return nil
	}
	if !validHex(invocation, 16) || s.invocation != invocation || s.description != "ANDEIVA cgroup retirement probe "+nonce || s.group != scopeProbeGroupV3 {
		return ErrIdentity
	}
	_, err = scopeProbeCommandV3(ctx, scopeProbeStopV3, "")
	return err
}
func scopeProbeStartOwnedV3(t *testing.T) (scopeProbeStateV3, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	before, err := scopeProbeStateReadV3(ctx)
	if err != nil || before.load != "not-found" {
		t.Fatal("probe unit must be absent", err)
	}
	var seed [16]byte
	if _, err = rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(seed[:])
	_, startErr := scopeProbeCommandV3(ctx, scopeProbeStartV3, nonce)
	invocation := ""
	// Registered as soon as creation returns, including uncertain submission.
	t.Cleanup(func() {
		if err := scopeProbeStopOwnedV3(invocation, nonce); err != nil {
			t.Error("owned probe cleanup refused or failed", err)
		}
	})
	capture, captureCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer captureCancel()
	state, err := scopeProbeStateReadV3(capture)
	if err == nil && state.description == "ANDEIVA cgroup retirement probe "+nonce && validHex(state.invocation, 16) && state.group == scopeProbeGroupV3 {
		invocation = state.invocation
	}
	if startErr != nil || err != nil || invocation == "" || state.load != "loaded" {
		t.Fatal("probe creation identity", errors.Join(startErr, err))
	}
	pid, err := strconv.Atoi(state.pid)
	if err != nil || pid <= 1 {
		t.Fatal("probe process identity")
	}
	return state, nonce
}
func scopeProbeOpenV3(t *testing.T) (*os.File, *os.File, unix.Stat_t) {
	t.Helper()
	fd, err := unix.Open(scopeProbePathV3, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	directory := os.NewFile(uintptr(fd), "owned-cgroup-probe")
	t.Cleanup(func() { _ = directory.Close() })
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 {
		t.Fatal("probe is not root cgroup2 directory")
	}
	eventsFD, err := unix.Openat(fd, "cgroup.events", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	events := os.NewFile(uintptr(eventsFD), "owned-cgroup-events")
	t.Cleanup(func() { _ = events.Close() })
	var eventStat unix.Stat_t
	if unix.Fstat(eventsFD, &eventStat) != nil || unix.Fstatfs(eventsFD, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || eventStat.Dev != st.Dev || eventStat.Mode&unix.S_IFMT != unix.S_IFREG {
		t.Fatal("events file not bound to cgroup2")
	}
	return directory, events, st
}
func scopeProbeEventsV3(file *os.File) (string, error) {
	raw := make([]byte, 4096)
	n, err := file.ReadAt(raw, 0)
	if n == len(raw) {
		return "", ErrIdentity
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return string(raw[:n]), err
}
func scopeProbePopulatedV3(raw string, want string) bool {
	seen := map[string]bool{}
	found := ""
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 || seen[parts[0]] || (parts[1] != "0" && parts[1] != "1") {
			return false
		}
		seen[parts[0]] = true
		switch parts[0] {
		case "populated":
			found = parts[1]
		case "frozen":
		default:
			return false
		}
	}
	return len(seen) == 2 && found == want
}

// This opt-in qualification records kernel behavior; it creates no production
// drainage rule and never interprets an errno as authority to issue a receipt.
func TestRoutedScopeCgroupNativeV3RetainedEventsAfterRecreation(t *testing.T) {
	if os.Getenv("ANDEIVA_ROUTED_SCOPE_CGROUP_NATIVE") != "1" {
		t.Skip("explicit Debian13 root cgroup qualification only")
	}
	if os.Getenv("CI") != "" || os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("native root qualification required outside CI")
	}
	release, err := os.ReadFile("/etc/os-release")
	if err != nil || len(release) > 16384 || !strings.Contains(string(release), "ID=debian\n") || !strings.Contains(string(release), "VERSION_ID=\"13\"\n") {
		t.Fatal("Debian13 required")
	}
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || strings.Contains(string(self), scopeProbeGroupV3) {
		t.Fatal("observer must be outside probe cgroup")
	}
	for _, path := range []string{"/usr/bin/systemctl", "/usr/bin/systemd-run", "/usr/bin/sleep"} {
		if trustedRoutedExecutableV3(path) != nil {
			t.Fatal("untrusted fixed test executable")
		}
	}
	first, nonce := scopeProbeStartOwnedV3(t)
	oldDir, oldEvents, old := scopeProbeOpenV3(t)
	live, err := scopeProbeEventsV3(oldEvents)
	if err != nil || !scopeProbePopulatedV3(live, "1") {
		t.Fatal("old cgroup not live", err)
	}
	members, err := os.ReadFile(scopeProbePathV3 + "/cgroup.procs")
	if err != nil || strings.TrimSpace(string(members)) != first.pid {
		t.Fatal("probe has unexpected processes")
	}
	var current unix.Stat_t
	if unix.Stat(scopeProbePathV3, &current) != nil || current.Dev != old.Dev || current.Ino != old.Ino {
		t.Fatal("probe path identity changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	checked, err := scopeProbeStateReadV3(ctx)
	cancel()
	if err != nil || checked.invocation != first.invocation || checked.description != first.description {
		t.Fatal("probe ownership changed before removal negative")
	}
	if err = unix.Rmdir(scopeProbePathV3); !errors.Is(err, unix.EBUSY) {
		t.Fatal("live owned cgroup rmdir must return EBUSY", err)
	}
	if err = scopeProbeStopOwnedV3(first.invocation, nonce); err != nil {
		t.Fatal("first probe stop", err)
	}
	scopeProbeWaitAbsentV3(t)
	retired, retiredErr := scopeProbeEventsV3(oldEvents)
	t.Logf("old_events_after_stop bytes=%q error=%v", retired, retiredErr)
	second, secondNonce := scopeProbeStartOwnedV3(t)
	_, newEvents, fresh := scopeProbeOpenV3(t)
	if first.invocation == second.invocation || old.Dev != fresh.Dev || old.Ino == fresh.Ino {
		t.Fatal("recreated scope did not obtain distinct identity")
	}
	var retained unix.Stat_t
	if unix.Fstat(int(oldDir.Fd()), &retained) != nil || retained.Dev != old.Dev || retained.Ino != old.Ino {
		t.Fatal("retained old directory identity changed")
	}
	newLive, err := scopeProbeEventsV3(newEvents)
	if err != nil || !scopeProbePopulatedV3(newLive, "1") {
		t.Fatal("recreated cgroup not live", err)
	}
	oldAfter, oldErr := scopeProbeEventsV3(oldEvents)
	t.Logf("old_events_after_recreate bytes=%q error=%v old_inode=%d new_inode=%d old_nlink=%d", oldAfter, oldErr, old.Ino, fresh.Ino, retained.Nlink)
	if scopeProbePopulatedV3(oldAfter, "1") || (oldErr == nil && !scopeProbePopulatedV3(oldAfter, "0")) || (oldErr != nil && (!errors.Is(oldErr, unix.ENODEV) || oldAfter != "")) {
		t.Fatal("retained events isolation unproven", oldErr)
	}
	if retiredErr == nil && !scopeProbePopulatedV3(retired, "0") || retiredErr != nil && (!errors.Is(retiredErr, unix.ENODEV) || retired != "") {
		t.Fatal("unexpected old events result after stop", retiredErr)
	}
	if err = scopeProbeStopOwnedV3(second.invocation, secondNonce); err != nil {
		t.Fatal("second probe stop", err)
	}
	scopeProbeWaitAbsentV3(t)
	t.Log("fixed probe lifecycle verified; no production retirement or namespace effects; old errno is observational only")
}

func TestRoutedScopeCgroupProbeParserV3(t *testing.T) {
	if !scopeProbePopulatedV3("populated 1\nfrozen 0\n", "1") || !scopeProbePopulatedV3("frozen 1\npopulated 0\n", "0") {
		t.Fatal("valid observation refused")
	}
	for _, raw := range []string{"", "populated 1\n", "populated 0\npopulated 1\nfrozen 0\n", "populated 2\nfrozen 0\n", "populated 0\nfrozen 0\nother 0\n"} {
		if scopeProbePopulatedV3(raw, "0") || scopeProbePopulatedV3(raw, "1") {
			t.Fatal("invalid observation accepted")
		}
	}
}

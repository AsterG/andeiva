//go:build linux

package networkexecutor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkplan"
	"golang.org/x/sys/unix"
)

const leaseNativeUID = 62006

// These tests exercise the real owned-namespace constructor and ip transport.
// Facts come from a deterministic test authority, not a DHCP protocol fixture.
func nativeLeaseInputs(t *testing.T, role string) (*os.File, *os.File, OwnedNamespaceIdentity, LeaseOptions, *LeaseFact) {
	t.Helper()
	if os.Getenv("ANDEIVA_LEASE_NATIVE") != "1" || os.Getenv("ANDEIVA_LEASE_ROLE") != role {
		t.Skip("requires the authorized native Debian isolated harness")
	}
	if os.Getenv("CI") != "" || os.Getuid() != leaseNativeUID || os.Getgid() != leaseNativeUID {
		t.Fatal("native identity denied")
	}
	version, err := os.ReadFile("/proc/version")
	if err != nil || strings.Contains(strings.ToLower(string(version)), "microsoft") {
		t.Fatal("native platform denied")
	}
	host, target := os.NewFile(3, "native-host-pin"), os.NewFile(4, "native-target-pin")
	if host == nil || target == nil {
		t.Fatal("missing namespace pins")
	}
	t.Cleanup(func() { _ = host.Close(); _ = target.Close() })
	hostID, err := namespaceID(int(host.Fd()))
	if err != nil {
		t.Fatal("host pin", err)
	}
	targetID, err := namespaceID(int(target.Fd()))
	if err != nil || targetID == hostID {
		t.Fatal("target pin denied")
	}
	for _, file := range []*os.File{host, target} {
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
			t.Fatal("namespace pin is not read only")
		}
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal("boot identity", err)
	}
	id := OwnedNamespaceIdentity{UID: leaseNativeUID, GID: leaseNativeUID, Host: hostID, Namespace: targetID, BootID: strings.TrimSpace(string(boot)), RunID: nativeLeaseNonce(t)}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal("owner process identity", err)
	}
	_, tail, ok := strings.Cut(string(stat), ") ")
	fields := strings.Fields(tail)
	if !ok || len(fields) < 20 {
		t.Fatal("owner process record")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	pid := os.Getpid()
	if err != nil || start == 0 || pid <= 1 || uint64(pid) > uint64(^uint32(0)) {
		t.Fatal("owner process identity invalid")
	}
	owner := LeaseOwner{Namespace: targetID, BootID: id.BootID, RunID: id.RunID, Incarnation: nativeLeaseNonce(t), PID: uint32(pid), StartTicks: start}
	r := fixturePlan()
	r.Config.Interfaces[1].IPv4 = networkplan.IPv4{Mode: "dhcp"}
	r, err = networkplan.Canonical(r.Config)
	if err != nil {
		t.Fatal(err)
	}
	fact := &LeaseFact{Owner: owner, Sequence: 1, DesiredHash: r.Hash, WAN: r.Config.Interfaces[1].Binding, Address: "198.19.0.10/24", Gateway: "198.19.0.2", DeadlineBootNS: nativeLeaseNow(t) + int64(time.Minute)}
	options := LeaseOptions{Desired: r, Owner: owner, Current: func(context.Context) (LeaseFact, error) { return *fact, nil }}
	status, err := readOwnedIdentityFile(false)
	if err != nil {
		t.Fatal(err)
	}
	if role != "capless" {
		if ownedPrivileges(status, leaseNativeUID, leaseNativeUID) != nil {
			t.Fatal("helper privilege profile denied")
		}
	} else {
		count := 0
		for _, line := range strings.Split(string(status), "\n") {
			key, value, _ := strings.Cut(line, ":")
			switch key {
			case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
				if strings.TrimSpace(value) != "0000000000000000" {
					t.Fatal("capless process retained capabilities")
				}
				count++
			case "NoNewPrivs":
				if strings.TrimSpace(value) != "1" {
					t.Fatal("no_new_privs missing")
				}
				count++
			}
		}
		if count != 6 {
			t.Fatal("capless status incomplete")
		}
	}
	t.Logf("role=%s pid=%d uid=%d gid=%d target=%d host=%d nnp=1 readonly_pins=2", role, pid, os.Getuid(), os.Getgid(), targetID, hostID)
	return target, host, id, options, fact
}

func nativeLeaseNonce(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

func nativeLeaseNow(t *testing.T) int64 {
	t.Helper()
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		t.Fatal(err)
	}
	return now.Nano()
}

func TestNativeLeaseCaplessDenied(t *testing.T) {
	target, host, id, options, _ := nativeLeaseInputs(t, "capless")
	l, err := NewLeaseInOwnedNamespace(context.Background(), target, host, id, 0, options)
	if l != nil || !errors.Is(err, ErrScope) {
		t.Fatal("capless constructor accepted", err)
	}
}

func TestNativeLeaseOccupiedDenied(t *testing.T) {
	target, host, id, options, _ := nativeLeaseInputs(t, "occupied")
	l, err := NewLeaseInOwnedNamespace(context.Background(), target, host, id, 0, options)
	if l != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatal("new process adopted occupied WAN", err)
	}
}

func TestNativeLeaseLifecycle(t *testing.T) {
	target, host, id, options, fact := nativeLeaseInputs(t, "helper")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	l, err := NewLeaseInOwnedNamespace(ctx, target, host, id, 0, options)
	if err != nil {
		t.Fatal("constructor", err)
	}
	defer func() { _, _ = l.Withdraw(context.Background()); _ = l.Close() }()
	physicalRun := l.base.run
	mutations := 0
	l.base.run = func(ctx context.Context, op operation) ([]byte, error) {
		if strings.HasSuffix(op.kind, "-add") || strings.HasSuffix(op.kind, "-delete") {
			mutations++
		}
		return physicalRun(ctx, op)
	}
	baseline := l.baseline
	assertBaseline := func(stage string) {
		t.Helper()
		actual, err := l.base.observe(ctx)
		if err != nil || !reflect.DeepEqual(actual, baseline) {
			t.Fatalf("%s: physical LAN/empty-WAN baseline changed: %v", stage, err)
		}
		t.Log(stage + ": exact physical baseline")
	}
	apply := func(stage string) {
		t.Helper()
		out, err := l.Refresh(ctx)
		if err != nil || out != LeaseApplied || l.Verify(ctx) != nil {
			t.Fatalf("%s: %s %v", stage, out, err)
		}
		t.Log(stage + ": physical WAN delta and preserved LAN verified")
	}
	assertBaseline("constructor read-only")
	apply("initial grant")
	if l.Close() != ErrBusy {
		t.Fatal("close abandoned active WAN")
	}
	if _, err := l.Refresh(ctx); !errors.Is(err, ErrScope) {
		t.Fatal("replay accepted", err)
	}
	// A separate real process has no in-memory ownership and must not adopt WAN.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestNativeLeaseOccupiedDenied$", "-test.v", "-test.timeout=15s") // #nosec G204 -- Same root-owned test executable; fixed test role and arguments.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "ANDEIVA_LEASE_NATIVE=1", "ANDEIVA_LEASE_ROLE=occupied"}
	cmd.ExtraFiles = []*os.File{host, target}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	runtime.LockOSThread()
	output, childErr := cmd.CombinedOutput()
	runtime.UnlockOSThread()
	if childErr != nil || !strings.Contains(string(output), "--- PASS: TestNativeLeaseOccupiedDenied (") || strings.Contains(string(output), "--- SKIP:") {
		t.Fatalf("occupied WAN process negative: %v: %.4096s", childErr, output)
	}
	t.Log("new process occupied-WAN denial passed")
	fact.Sequence++
	fact.DeadlineBootNS = nativeLeaseNow(t) + int64(90*time.Second)
	beforeRenew := mutations
	if out, err := l.Refresh(ctx); err != nil || out != LeaseEvidenceRefreshed || l.Verify(ctx) != nil || mutations != beforeRenew {
		t.Fatal("same tuple renewal", out, err)
	}
	t.Log("renewal: retained tuple, renewed in-memory evidence")
	fact.Sequence++
	fact.Address = "198.19.0.11/24"
	apply("changed lease")
	fact.Sequence++
	fact.Revoked, fact.Address, fact.Gateway, fact.DeadlineBootNS = true, "", "", 0
	if out, err := l.Refresh(ctx); out != LeaseWANWithdrawn || !errors.Is(err, ErrLeaseUnavailable) {
		t.Fatal("revocation", out, err)
	}
	assertBaseline("revocation")
	fact.Sequence++
	fact.Revoked, fact.Address, fact.Gateway = false, "198.19.0.12/24", "198.19.0.2"
	fact.DeadlineBootNS = nativeLeaseNow(t) + int64(5*time.Second)
	apply("short lease")
	remaining := time.Duration(fact.DeadlineBootNS-nativeLeaseNow(t)) + 20*time.Millisecond
	if remaining > 0 {
		time.Sleep(remaining)
	}
	if l.Verify(ctx) == nil {
		t.Fatal("expired authority verified")
	}
	if out, err := l.Refresh(ctx); out != LeaseWANWithdrawn || !errors.Is(err, ErrLeaseUnavailable) {
		t.Fatal("expiry withdrawal", out, err)
	}
	assertBaseline("expiry")
	fact.Sequence++
	fact.Address, fact.DeadlineBootNS = "198.19.0.13/24", nativeLeaseNow(t)+int64(time.Minute)
	apply("explicit withdrawal grant")
	if out, err := l.Withdraw(ctx); err != nil || out != LeaseBaselineRestored {
		t.Fatal("explicit withdrawal", out, err)
	}
	assertBaseline("explicit withdrawal")
	// Do not replace kernel observations: revoke the test authority immediately
	// AFTER the real final links read, following the real route readback.
	prior := l.base.run
	routeAdded, routesRead, revoked := false, false, false
	l.base.run = func(ctx context.Context, op operation) ([]byte, error) {
		b, err := prior(ctx, op)
		if err == nil {
			switch {
			case op.kind == "route-add":
				routeAdded = true
			case routeAdded && op.kind == "routes":
				routesRead = true
			case routesRead && op.kind == "links" && !revoked:
				fact.Sequence++
				fact.Revoked, fact.Address, fact.Gateway, fact.DeadlineBootNS = true, "", "", 0
				revoked = true
			}
		}
		return b, err
	}
	fact.Sequence++
	fact.Address, fact.DeadlineBootNS = "198.19.0.14/24", nativeLeaseNow(t)+int64(time.Minute)
	out, err := l.Refresh(ctx)
	l.base.run = prior
	if !revoked || out != LeaseBaselineRestored || !errors.Is(err, ErrLeaseUnavailable) {
		t.Fatal("final readback authority fence", revoked, out, err)
	}
	assertBaseline("final readback revocation compensation")
	if err := l.Close(); err != nil {
		t.Fatal("close restored executor", err)
	}
	// Empty WAN after explicit restoration may be opened by a fresh executor.
	reopened, err := NewLeaseInOwnedNamespace(ctx, target, host, id, 0, options)
	if err != nil {
		t.Fatal("empty baseline reopen", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

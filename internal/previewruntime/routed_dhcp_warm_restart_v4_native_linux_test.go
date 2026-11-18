//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/jsoncheck"
	"golang.org/x/sys/unix"
)

const nativeDHCPWarmMarkerV4 = "native-warm-restart"

func TestNativeRoutedDHCPWarmRestartV4(t *testing.T) {
	nativeRunRoutedDHCPScenarioV4(t, true, 0, "healthy")
}

func nativeDHCPWarmProfileV4() (bool, error) {
	base, err := os.Open("/proc/self/fd/5/..")
	if err != nil {
		return false, err
	}
	defer base.Close()
	var parent unix.Stat_t
	if unix.Fstat(int(base.Fd()), &parent) != nil || parent.Uid != 0 || parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Mode&0022 != 0 {
		return false, ErrIdentity
	}
	fd, err := unix.Openat(int(base.Fd()), nativeDHCPWarmMarkerV4, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(fd), nativeDHCPWarmMarkerV4)
	defer file.Close()
	var marker unix.Stat_t
	if unix.Fstat(fd, &marker) != nil || marker.Uid != 0 || marker.Mode != unix.S_IFREG|0444 || marker.Nlink != 1 || marker.Size < 4 || marker.Size > 7 {
		return false, ErrIdentity
	}
	data, err := io.ReadAll(io.LimitReader(file, 8))
	if err != nil {
		return false, err
	}
	switch string(data) {
	case "healthy", "store", "helper", "both":
		return true, nil
	default:
		return false, ErrIdentity
	}
}

func nativeDHCPWarmRootV4(t *testing.T, ctx context.Context, base string, namespaces [3]*os.File, supervisor *RoutedLaunchSupervisorV3, logs *nativeLogV3, bound nativeDHCPJobsReportV4) {
	t.Helper()
	nativeDHCPContinuitySourceV4(t, ctx, namespaces[1])
	flow, err := startNativeDHCPContinuityProfileV4(t, ctx, namespaces[1], namespaces[2], continuityDefaultV4)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Stop()
	sample := func() int64 {
		var stamp unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &stamp); err != nil {
			t.Fatal(err)
		}
		return stamp.Nano()
	}
	if _, err := flow.Checkpoint(ctx, sample()); err != nil {
		t.Fatal("TCP/UDP before restart", err)
	}
	selector := filepath.Join(base, "store", "selected.json")
	before, err := os.ReadFile(selector)
	if err != nil {
		t.Fatal(err)
	}
	oldHelper, oldAPI := supervisor.PIDs()
	started := sample()
	if err = supervisor.RestartAPI(ctx); err != nil {
		t.Fatalf("warm API launch: %v\n%s", err, logs.String())
	}
	helper, api := supervisor.PIDs()
	if helper != oldHelper || api <= 1 || api == oldAPI {
		t.Fatal("restart changed helper or retained the old API")
	}
	restarted := nativeDHCPJobsWaitReportV4(t, ctx, logs, "restarted")
	after, err := os.ReadFile(selector)
	if err != nil || !bytes.Equal(before, after) || restarted.Running != bound.Running || !reflect.DeepEqual(restarted.Grant, bound.Grant) {
		t.Fatal("restart changed selection, owner or grant", err)
	}
	nativeDHCPJobsKernelV4(t, ctx, namespaces[0], restarted.Grant.Snapshot)
	if _, err := flow.Checkpoint(ctx, sample()); err != nil {
		t.Fatal("TCP/UDP after restart", err)
	}
	report, err := flow.Stop()
	if err != nil || report.TCPAccepted != 1 || report.TCPDisconnects != 0 || report.UDPTupleChanges != 0 || report.UDPSent == 0 || report.UDPUniqueEchoes == 0 {
		t.Fatalf("persistent flow: %v, TCP connections=%d, UDP tuple changes=%d", err, report.TCPAccepted, report.UDPTupleChanges)
	}
	t.Logf("API stopped to post-restart TCP/UDP checkpoint: %d ns, TCP retransmissions %d, UDP missing %d/%d", sample()-started, report.TCPTotalRetrans, report.UDPMissingEchoes, report.UDPSent)
	supervisor.mu.Lock()
	err = supervisor.api.cmd.Process.Signal(syscall.SIGUSR2)
	supervisor.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	nativeDHCPJobsWaitReportV4(t, ctx, logs, "rollback-fenced")
}

func TestNativeRoutedDHCPWarmRestartNoStoreV4(t *testing.T) {
	nativeRunRoutedDHCPScenarioV4(t, true, 0, "store")
}

func TestNativeRoutedDHCPWarmRestartNoHelperV4(t *testing.T) {
	nativeRunRoutedDHCPScenarioV4(t, true, 0, "helper")
}

func TestNativeRoutedDHCPWarmRestartNoDependenciesV4(t *testing.T) {
	nativeRunRoutedDHCPScenarioV4(t, true, 0, "both")
}

type nativeDHCPWarmTokenV4 struct {
	Value   string `json:"val"`
	Comment string `json:"comment"`
	Timeout int64  `json:"timeout"`
	Expires int64  `json:"expires"`
}

func nativeDHCPWarmTokenAtV4(ctx context.Context, gateway *os.File) (nativeDHCPWarmTokenV4, error) {
	var document struct {
		Objects []struct {
			Set *struct {
				Family, Table, Name string
				Elements            []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	raw, err := nativeDHCPB2CommandV4(ctx, gateway, "/usr/sbin/nft", "-j", "-n", "-y", "list", "table", "inet", "andeiva_lease_gate")
	if err != nil || len(raw) > 64<<10 || !jsoncheck.UniqueControlFields(raw) || json.Unmarshal(raw, &document) != nil {
		return nativeDHCPWarmTokenV4{}, ErrUnavailable
	}
	var token nativeDHCPWarmTokenV4
	found := false
	for _, object := range document.Objects {
		if s := object.Set; s != nil && s.Family == "inet" && s.Table == "andeiva_lease_gate" && s.Name == "live" {
			if found || len(s.Elements) > 1 {
				return nativeDHCPWarmTokenV4{}, ErrIdentity
			}
			found = true
			if len(s.Elements) == 1 {
				var element struct {
					Token nativeDHCPWarmTokenV4 `json:"elem"`
				}
				if json.Unmarshal(s.Elements[0], &element) != nil {
					return nativeDHCPWarmTokenV4{}, ErrIdentity
				}
				token = element.Token
				if token.Value != "wan0" || !routedPrivateHashV4(token.Comment) || token.Expires < 0 || token.Expires > token.Timeout {
					return nativeDHCPWarmTokenV4{}, ErrIdentity
				}
			}
		}
	}
	if !found {
		return nativeDHCPWarmTokenV4{}, ErrIdentity
	}
	return token, nil
}

func nativeDHCPWarmUnavailableV4(t *testing.T, ctx context.Context, mode, base string, namespaces [3]*os.File, supervisor *RoutedLaunchSupervisorV3, earlyResponseTimedOut *atomic.Bool, stopServer func(), bound nativeDHCPJobsReportV4) {
	t.Helper()
	clock := func() int64 {
		var stamp unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &stamp); err != nil {
			t.Fatal(err)
		}
		return stamp.Nano()
	}
	nativeDHCPContinuitySourceV4(t, ctx, namespaces[1])
	flow, err := startNativeDHCPContinuityProfileV4(t, ctx, namespaces[1], namespaces[2], continuityDefaultV4)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Stop()
	if _, err = flow.Checkpoint(ctx, clock()); err != nil {
		t.Fatal("TCP/UDP before outage", err)
	}
	stopServer()
	selector := filepath.Join(base, "store", "selected.json")
	selected, err := os.ReadFile(selector)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := nativeDHCPWarmTokenAtV4(ctx, namespaces[0])
	at := clock()
	if err != nil || initial.Expires < 50 {
		t.Fatal("initial live token missing or too close to expiry", initial, err)
	}
	hasStore := mode != "store" && mode != "both"
	hasHelper := mode != "helper" && mode != "both"
	if !hasStore {
		info, err := os.Stat(selector)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(selector, 0); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chmod(selector, info.Mode().Perm()); err != nil {
				t.Error("restore fixture selector mode", err)
			}
		}()
	}
	helperPID, _ := supervisor.PIDs()
	if !hasHelper {
		supervisor.mu.Lock()
		process := supervisor.helper.cmd.Process
		err := process.Signal(syscall.SIGSTOP)
		supervisor.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		defer process.Signal(syscall.SIGCONT)
	}
	if err = supervisor.RestartAPI(ctx); err == nil {
		t.Fatal("API became ready without its required dependency")
	}
	if helper, api := supervisor.PIDs(); helper != helperPID || api != 0 {
		t.Fatal("helper changed or failed API was not drained")
	}
	if _, err := flow.Checkpoint(ctx, clock()); err != nil {
		t.Fatal("TCP/UDP lost while the existing permit should still be live", err)
	}
	last := initial.Expires
	var closedAt int64
	closedBy := "kernel timeout"
	for {
		actual, err := nativeDHCPWarmTokenAtV4(ctx, namespaces[0])
		if err != nil {
			t.Fatal("read active token", err)
		}
		now := clock()
		if !hasHelper && now > bound.Grant.Snapshot.DeadlineBootNS+int64(time.Second) {
			t.Fatal("kernel permit exceeded original deadline")
		}
		if actual == (nativeDHCPWarmTokenV4{}) {
			if now < at+(initial.Expires-2)*int64(time.Second) {
				// With the helper present, B1's independent, verified
				// response timeout still revokes earlier when the isolated
				// provider is absent. Management may not cause that cut.
				if !hasHelper {
					t.Fatal("permit withdrawn before original kernel expiry")
				}
				closedBy = "independent DHCP response timeout"
			}
			closedAt = now
			break
		}
		if actual.Comment != initial.Comment || actual.Timeout != initial.Timeout || actual.Expires > last ||
			now > bound.Grant.Snapshot.DeadlineBootNS+int64(time.Second) {
			t.Fatal("original token changed or outlived its deadline")
		}
		last = actual.Expires
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(time.Second)
	if actual, err := nativeDHCPWarmTokenAtV4(ctx, namespaces[0]); err != nil || actual != (nativeDHCPWarmTokenV4{}) {
		t.Fatal("token reappeared while a dependency was missing", err)
	}
	if closedBy != "kernel timeout" && !earlyResponseTimedOut.Load() {
		t.Fatal("permit withdrawn before expiry without independent DHCP timeout")
	}
	end := clock()
	traffic, err := flow.Stop()
	if err != nil || traffic.TCPAccepted != 1 || traffic.TCPDisconnects != 0 || traffic.UDPTupleChanges != 0 || traffic.TCPLastEchoBootNS > closedAt {
		t.Fatalf("unexpected TCP/UDP after expiry: %v, TCP connections=%d", err, traffic.TCPAccepted)
	}
	closed := nativeDHCPB2ClosedProofV4{BootNS: closedAt, Sequence: bound.Grant.Snapshot.Sequence}
	evidence, err := nativeDHCPB2WaitTrafficEvidenceV4(traffic, nativeDHCPB2WaitProofV4{Enter: closed, LastClosed: closed, EndBootNS: end, EndReason: "original_kernel_timeout"})
	if err != nil {
		t.Fatal("traffic after original token expiry", evidence, err)
	}
	after, err := os.ReadFile(selector)
	if err != nil || !bytes.Equal(selected, after) {
		t.Fatal("failed API attempt changed selection", err)
	}
	t.Logf("dependencies=%s selection unchanged, closed by %s after %.3f s, forwarded UDP after close=%d/%d", mode, closedBy, time.Duration(closedAt-at).Seconds(), evidence.SinkReceipts, evidence.FullyBounded)
}

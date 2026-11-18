//go:build linux

package previewruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"golang.org/x/sys/unix"
)

const nativeDHCPB2MarkerV4 = "native-b2-profile"

func nativeDHCPB2ProfileValueV4(value string) (uint32, error) {
	switch value {
	case "":
		return 0, nil
	case "70":
		return 70, nil
	case "71":
		return 71, nil
	default:
		return 0, ErrIdentity
	}
}

func TestNativeRoutedDHCPB2Natural70V4(t *testing.T) {
	nativeRunRoutedDHCPScenarioV4(t, true, 70, "")
}
func TestNativeRoutedDHCPB2Natural71V4(t *testing.T) {
	nativeRunRoutedDHCPScenarioV4(t, true, 71, "")
}

func nativeDHCPB2WriteProfileV4(base string, seconds uint32) error {
	if os.Geteuid() != 0 || seconds != 70 && seconds != 71 {
		return ErrIdentity
	}
	f, err := os.OpenFile(filepath.Join(base, nativeDHCPB2MarkerV4), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = io.WriteString(f, strconv.FormatUint(uint64(seconds), 10)); err != nil {
		return err
	}
	return f.Chmod(0444)
}

// The optional marker is root-created in the pinned store's immutable parent;
// no environment value, caller path or product IPC can select an API behavior.
func nativeDHCPB2ReadProfileAtV4(base *os.File, uid uint32) (uint32, error) {
	var parent unix.Stat_t
	if base == nil || unix.Fstat(int(base.Fd()), &parent) != nil || parent.Uid != uid || parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Mode&0022 != 0 {
		return 0, ErrIdentity
	}
	fd, err := unix.Openat(int(base.Fd()), nativeDHCPB2MarkerV4, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	f := os.NewFile(uintptr(fd), "fixed-native-b2-profile")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uid || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0444 || st.Nlink != 1 || st.Size != 2 {
		return 0, ErrIdentity
	}
	raw, err := io.ReadAll(io.LimitReader(f, 3))
	if err != nil {
		return 0, err
	}
	p, err := nativeDHCPB2ProfileValueV4(string(raw))
	if p == 0 {
		return 0, ErrIdentity
	}
	return p, err
}

type nativeDHCPB2APIReportV4 struct {
	PID     int                         `json:"pid"`
	Phase   string                      `json:"phase"`
	Seconds uint32                      `json:"lease_seconds"`
	Work    string                      `json:"work"`
	Running string                      `json:"running"`
	Grant   configpoc.RoutedDHCPGrantV3 `json:"grant"`
}

func nativeDHCPB2EmitV4(phase string, seconds uint32, work, running string, grant configpoc.RoutedDHCPGrantV3) error {
	raw, err := json.Marshal(nativeDHCPB2APIReportV4{os.Getpid(), phase, seconds, work, running, grant})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stderr, "ANDEIVA_NATIVE_DHCP_B2_API_V4 %s\n", raw)
	return err
}

func nativeDHCPB2FreshLiveV2(observe func() (bool, error), emit func() error) (bool, error) {
	fresh, err := observe()
	if err != nil {
		return false, err
	}
	if !fresh {
		return false, nil
	}
	if err = emit(); err != nil {
		return false, err
	}
	return true, nil
}

func nativeDHCPB2ObserveControllerV2(ctx context.Context, c *RoutedDHCPControllerV3, observe func() (bool, error)) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// Queue one read behind active reconciliation. Repeated TryLock probes can
	// miss the gap between consecutive scheduler attempts.
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return observe()
}

func nativeDHCPB2ServeV4(ctx context.Context, r *RoutedOperationsRuntimeV3, binding adminauth.SessionBinding, launch RoutedLaunchContextV3, startup, running string, first configpoc.RoutedDHCPGrantV3, acks <-chan os.Signal) (bool, error) {
	base, err := os.Open("/proc/self/fd/5/..")
	if err != nil {
		return true, err
	}
	seconds, err := nativeDHCPB2ReadProfileAtV4(base, 0)
	base.Close()
	if err != nil || seconds == 0 {
		return seconds != 0 || err != nil, err
	}
	if !launch.DHCPRenewalV4 || launch.Epoch != 1 {
		return true, ErrIdentity
	}
	select {
	case <-acks:
	case <-ctx.Done():
		return true, ctx.Err()
	}
	r.DHCP.mu.Lock()
	work := r.DHCP.work
	r.DHCP.mu.Unlock()
	if work == "" {
		return true, ErrIdentity
	}
	if err = nativeDHCPB2EmitV4("ready", seconds, work, running, first); err != nil {
		return true, err
	}
	if seconds == 71 {
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			// Observe the autonomous controller only; do not manually Reconcile
			// away a missing recovery wake. Live is read-only verification.
			var grant configpoc.RoutedDHCPGrantV3
			complete, liveErr := nativeDHCPB2FreshLiveV2(func() (bool, error) {
				return nativeDHCPB2ObserveControllerV2(ctx, r.DHCP, func() (bool, error) {
					grant = r.DHCP.grant
					fresh := grant.Epoch > first.Epoch && !r.DHCP.recoveryOnly && r.DHCP.work == work && r.Service.RuntimeIntegrityReadyV1()
					if fresh {
						_, e := r.routed.Call(ctx, "dhcp_live", firewallipc.RoutedDHCPRequestV3{Work: work})
						return true, e
					}
					return false, nil
				})
			}, func() error { return nativeDHCPB2EmitV4("recovered", seconds, work, running, grant) })
			if liveErr != nil {
				return true, liveErr
			}
			if complete {
				break
			}
			select {
			case <-tick.C:
			case <-ctx.Done():
				return true, ctx.Err()
			}
		}
	}
	select {
	case <-acks:
	case <-ctx.Done():
		return true, ctx.Err()
	}
	r.DHCP.mu.Lock()
	same := r.DHCP.work == work
	grant := r.DHCP.grant
	r.DHCP.mu.Unlock()
	if !same || seconds == 70 && !reflect.DeepEqual(grant, first) {
		return true, errors.New("B2 replaced retained Work or promoted insufficient evidence")
	}
	if err = nativeDHCPB2EmitV4("before-retire", seconds, work, running, grant); err != nil {
		return true, err
	}
	if err = nativeDHCPJobsRetireV4(ctx, r, binding, startup); err != nil {
		return true, err
	}
	<-ctx.Done()
	return true, nil
}

type nativeDHCPB2GrantV4 struct {
	BootNS  int64
	Seconds uint32
	Reason  string
}
type nativeDHCPB2DiagnosticStateV4 struct {
	Grants       []nativeDHCPB2GrantV4
	Signals      []int64
	MarginBootNS int64
	MarginCount  int
	MarginReason string
	Ended        bool
	err          error
}
type nativeDHCPB2DiagnosticsV4 struct {
	mu    sync.Mutex
	state nativeDHCPB2DiagnosticStateV4
}

// Callback consumes the collector's already-read bounded snapshot. No RPC,
// filesystem operation or extra diagnostic reader runs here.
func (d *nativeDHCPB2DiagnosticsV4) observe(raw []byte) {
	var state nativeDHCPB2DiagnosticStateV4
	if len(raw) > 64<<10 {
		state.err = ErrUnavailable
	} else {
		scan := bufio.NewScanner(bytes.NewReader(raw))
		records := 0
		for scan.Scan() {
			records++
			var e struct {
				BootNS  int64  `json:"boot_ns"`
				Stage   string `json:"stage"`
				Detail  string `json:"detail"`
				Code    int    `json:"code"`
				Seconds uint32 `json:"lease_seconds"`
			}
			decoder := json.NewDecoder(bytes.NewReader(scan.Bytes()))
			decoder.DisallowUnknownFields()
			if records > 1024 || len(scan.Bytes()) > 512 || !jsoncheck.UniqueControlFields(scan.Bytes()) || decoder.Decode(&e) != nil || decoder.Decode(new(any)) != io.EOF || e.Stage == "truncated" || e.BootNS <= 0 {
				state.err = ErrUnavailable
				break
			}
			switch e.Stage {
			case "early_signal":
				state.Signals = append(state.Signals, e.BootNS)
			case "early_margin_closed":
				state.MarginCount++
				if state.MarginBootNS == 0 {
					state.MarginBootNS = e.BootNS
					state.MarginReason = e.Detail
				}
			case "event":
				if state.MarginBootNS > 0 && (e.Detail == "EXPIRE" || e.Detail == "FAIL" || e.Detail == "NOCARRIER") {
					state.err = errors.New("B2 lease continuity ended during WAIT")
				}
				if e.Detail == "BOUND" || e.Detail == "RENEW" || e.Detail == "REBIND" || e.Detail == "REBOOT" {
					state.Grants = append(state.Grants, nativeDHCPB2GrantV4{e.BootNS, e.Seconds, e.Detail})
				}
			case "owner_exit", "owner_exit_observed", "stopped":
				state.Ended = true
			}
			if len(state.Signals) > 16 || len(state.Grants) > 16 || state.MarginCount > 1 {
				state.err = ErrUnavailable
				break
			}
		}
		if scan.Err() != nil {
			state.err = scan.Err()
		}
	}
	d.mu.Lock()
	if d.state.err != nil {
		state.err = d.state.err
	}
	d.state = state
	d.mu.Unlock()
}

func (d *nativeDHCPB2DiagnosticsV4) snapshot() nativeDHCPB2DiagnosticStateV4 {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.state
	s.Grants = append([]nativeDHCPB2GrantV4(nil), s.Grants...)
	s.Signals = append([]int64(nil), s.Signals...)
	return s
}

func nativeDHCPB2SignalV4(s *RoutedLaunchSupervisorV3) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.api == nil || s.api.cmd.Process == nil {
		return ErrUnavailable
	}
	return s.api.cmd.Process.Signal(syscall.SIGUSR2)
}

func nativeDHCPB2ReportV4(log string, api int, phase string) (nativeDHCPB2APIReportV4, bool, error) {
	var result nativeDHCPB2APIReportV4
	found := false
	if !nativeDHCPEvidenceLogValidV4(log) {
		return result, false, ErrUnavailable
	}
	for _, line := range strings.Split(log, "\n") {
		raw, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_DHCP_B2_API_V4 ")
		if !ok {
			continue
		}
		var r nativeDHCPB2APIReportV4
		if !jsoncheck.UniqueFields([]byte(raw)) || json.Unmarshal([]byte(raw), &r) != nil || r.PID != api {
			return result, false, ErrIdentity
		}
		canonical, _ := json.Marshal(r)
		if !continuitySameShapeV4(canonical, []byte(raw)) {
			return result, false, ErrIdentity
		}
		if r.Phase == phase {
			if found {
				return result, false, ErrIdentity
			}
			result, found = r, true
		}
	}
	return result, found, nil
}

func nativeDHCPB2CommandV4(ctx context.Context, namespace *os.File, executable string, args ...string) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, "/usr/bin/nsenter", append([]string{"--net=/proc/self/fd/3", "--", executable}, args...)...)
	cmd.ExtraFiles = []*os.File{namespace}
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	var out nativeLogV3
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	if out.truncated {
		return nil, ErrUnavailable
	}
	return []byte(out.String()), nil
}

func nativeDHCPB2ClosedKernelV4(ctx context.Context, gateway *os.File) error {
	forward, err := nativeDHCPB2CommandV4(ctx, gateway, "/usr/bin/cat", "/proc/sys/net/ipv4/ip_forward")
	if err != nil || string(forward) != "0\n" {
		return ErrUnavailable
	}
	raw, err := nativeDHCPB2CommandV4(ctx, gateway, "/usr/sbin/nft", "-j", "-n", "-y", "list", "table", "inet", "andeiva_lease_gate")
	if err != nil {
		return ErrUnavailable
	}
	return nativeDHCPB2ClosedSetsV4(raw)
}

func nativeDHCPB2ClosedSetsV4(raw []byte) error {
	if len(raw) > 64<<10 || !jsoncheck.UniqueControlFields(raw) {
		return ErrUnavailable
	}
	var document struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &document) != nil || len(document.Objects) > 32 {
		return ErrUnavailable
	}
	sets := map[string]bool{}
	for _, object := range document.Objects {
		if data, ok := object["set"]; ok {
			var s struct {
				Family, Table, Name string
				Elements            []any `json:"elem"`
			}
			if json.Unmarshal(data, &s) != nil || s.Family != "inet" || s.Table != "andeiva_lease_gate" || s.Name != "enabled" && s.Name != "live" || len(s.Elements) != 0 || sets[s.Name] {
				return ErrUnavailable
			}
			sets[s.Name] = true
		}
	}
	if len(sets) != 2 {
		return ErrUnavailable
	}
	return nil
}

// The first post-mask RENEW is the unsafe grant. Only later RENEW hooks
// count as natural recovery; BOUND/REBOOT/REBIND cannot substitute for them.
func nativeDHCPB2RenewalsV4(seconds uint32, d nativeDHCPB2DiagnosticStateV4) (int, nativeDHCPB2GrantV4, error) {
	var natural nativeDHCPB2GrantV4
	if (seconds != 70 && seconds != 71) || d.err != nil || d.Ended || d.MarginBootNS <= 0 || d.MarginCount != 1 || len(d.Grants) > 16 {
		return 0, natural, ErrUnavailable
	}
	count := 0
	var previous int64
	for _, g := range d.Grants {
		if g.BootNS <= previous || g.Seconds == 0 {
			return 0, natural, ErrUnavailable
		}
		previous = g.BootNS
		if g.BootNS < d.MarginBootNS {
			continue
		}
		if g.Reason != "RENEW" || g.Seconds != seconds {
			return 0, natural, errors.New("B2 expected uninterrupted RENEW hooks")
		}
		count++
		if count == 2 && seconds == 70 || count == 1 && seconds == 71 {
			natural = g
		}
	}
	return count, natural, nil
}

func nativeDHCPB2NoProbeV4(seconds uint32, d nativeDHCPB2DiagnosticStateV4) error {
	if d.MarginBootNS <= 0 || d.MarginCount != 1 {
		return ErrUnavailable
	}
	wantReason := "early_short_lease"
	if seconds == 71 {
		wantReason = "early_dispatch_late"
	}
	if d.MarginReason != wantReason {
		return errors.New("B2 did not exercise selected mask reason")
	}
	_, natural, err := nativeDHCPB2RenewalsV4(seconds, d)
	if err != nil {
		return err
	}
	var naturalAt int64
	if seconds == 71 {
		naturalAt = natural.BootNS
	}
	before := 0
	for _, at := range d.Signals {
		if at < d.MarginBootNS {
			before++
		} else if naturalAt == 0 || at < naturalAt {
			return errors.New("active recovery signal during B2 WAIT")
		}
	}
	want := 1
	if seconds == 71 {
		want = 0
	}
	if before != want {
		return errors.New("B2 request count differs from fixed fixture profile")
	}
	return nil
}

func nativeDHCPB2StoreDigestV4(base string) ([32]byte, error) {
	h := sha256.New()
	entries, read := 0, int64(0)
	err := filepath.WalkDir(filepath.Join(base, "store"), func(path string, e fs.DirEntry, err error) error {
		entries++
		if err != nil {
			return err
		}
		if entries > 20000 || e.Type()&os.ModeSymlink != 0 {
			return ErrUnavailable
		}
		if e.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() < 0 || st.Size() > 32<<20-read {
			return ErrUnavailable
		}
		read += st.Size()
		fmt.Fprintf(h, "%s:%d\n", strings.TrimPrefix(path, base), st.Size())
		n, err := io.Copy(h, io.LimitReader(f, st.Size()+1))
		if n != st.Size() {
			return ErrUnavailable
		}
		return err
	})
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, err
}

func nativeDHCPB2ServerV4(t *testing.T, ctx context.Context, base string, wan *os.File, seconds uint32, logs io.Writer) func() {
	t.Helper()
	if seconds != 70 && seconds != 71 || trustedRoutedExecutableV3("/usr/bin/busybox") != nil {
		t.Fatal("invalid B2 test peer")
	}
	path := filepath.Join(base, "b2-server.conf")
	// This replacement peer has no dynamic lease history. Pin the existing lab
	// client so it can ACK a real unicast RENEW instead of silently ignoring it.
	conf := fmt.Sprintf("start 198.18.1.10\nend 198.18.1.10\ninterface sink0\nmax_leases 1\nmin_lease 60\nstatic_lease 02:00:00:00:02:01 198.18.1.10\nlease_file %s\npidfile %s\nopt subnet 255.255.255.0\nopt router 198.18.1.1\nopt lease %d\n", filepath.Join(base, "b2-server.leases"), filepath.Join(base, "b2-server.pid"), seconds)
	if err := os.WriteFile(path, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", "/usr/bin/busybox", "udhcpd", "-f", path)
	cmd.ExtraFiles = []*os.File{wan}
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = logs, logs
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	started, done := make(chan error, 1), make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := cmd.Start()
		started <- err
		if err == nil {
			err = cmd.Wait()
		}
		done <- err
	}()
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	return func() { once.Do(func() { _ = cmd.Process.Kill(); <-done }) }
}

type nativeDHCPB2ClosedProofV4 struct {
	BootNS   int64  `json:"verified_boot_ns"`
	Sequence uint64 `json:"closed_sequence"`
}
type nativeDHCPB2WaitProofV4 struct {
	Enter      nativeDHCPB2ClosedProofV4 `json:"enter"`
	LastClosed nativeDHCPB2ClosedProofV4 `json:"last_closed_before_end"`
	EndBootNS  int64                     `json:"end_boot_ns"`
	EndReason  string                    `json:"end_reason"`
}
type nativeDHCPB2WaitTrafficV4 struct {
	FullyBounded      uint64 `json:"writes_fully_inside_wait"`
	SinkReceipts      uint64 `json:"sink_receipts_of_fully_bounded_writes"`
	BoundaryAmbiguous uint64 `json:"writes_crossing_wait_boundary_excluded"`
	PriorExcluded     uint64 `json:"writes_before_wait_excluded"`
}

func nativeDHCPB2ClosedProofAtV4(log string, helper int, at int64, sequence uint64) (nativeDHCPB2ClosedProofV4, error) {
	proof := nativeDHCPB2ClosedProofV4{at, sequence}
	if helper <= 1 || at <= 0 || sequence == 0 || !nativeDHCPEvidenceLogValidV4(log) {
		return proof, ErrIdentity
	}
	var closed uint64
	for _, line := range strings.Split(log, "\n") {
		raw, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_LEASE_PHASE_V4 ")
		if !ok {
			continue
		}
		var phase nativeLeasePhaseEvidenceV4
		if routedDHCPOwnerDecodeV3([]byte(raw), &phase) != nil || phase.PID != helper || phase.BootNS <= 0 {
			return proof, ErrIdentity
		}
		if phase.BootNS > at {
			continue
		}
		switch phase.Phase {
		case "closed":
			closed = phase.Sequence
		case "close_start", "open_start", "opened":
			closed = 0
		default:
			return proof, ErrIdentity
		}
	}
	if closed != sequence {
		return proof, errors.New("closed readback lacks same retained fence evidence")
	}
	return proof, nil
}

func nativeDHCPB2WaitTrafficEvidenceV4(r nativeDHCPContinuityReportV4, proof nativeDHCPB2WaitProofV4) (nativeDHCPB2WaitTrafficV4, error) {
	var result nativeDHCPB2WaitTrafficV4
	if proof.Enter.BootNS <= 0 || proof.Enter.Sequence == 0 || proof.LastClosed.Sequence != proof.Enter.Sequence || proof.LastClosed.BootNS < proof.Enter.BootNS || proof.EndBootNS < proof.LastClosed.BootNS {
		return result, ErrIdentity
	}
	for seq := uint64(1); seq <= continuityLimitV4; seq++ {
		if !r.UDPSentSet.has(seq) {
			continue
		}
		start, end := r.UDPSendStartBootNS[seq], r.UDPSendEndBootNS[seq]
		if start <= 0 || end < start {
			return result, ErrIdentity
		}
		if end < proof.Enter.BootNS {
			result.PriorExcluded++
			continue
		}
		if start < proof.Enter.BootNS || start <= proof.EndBootNS && end > proof.EndBootNS {
			result.BoundaryAmbiguous++
			continue
		}
		if start > proof.EndBootNS {
			continue
		}
		result.FullyBounded++
		if r.UDPSinkReceivedSet.has(seq) {
			result.SinkReceipts++
		}
	}
	if result.FullyBounded == 0 || result.SinkReceipts != 0 {
		return result, errors.New("UDP datagram crossed B2 WAIT or no bounded writes were observed")
	}
	return result, nil
}

func nativeDHCPB2InitialHookV2(log string, helper int, grant configpoc.RoutedDHCPGrantV3) (int64, error) {
	var initial int64
	if helper <= 1 || grant.Epoch == 0 || grant.Snapshot.Sequence == 0 {
		return 0, ErrIdentity
	}
	for _, line := range strings.Split(log, "\n") {
		raw, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_LEASE_HOOK_V4 ")
		if !ok {
			continue
		}
		var h nativeDHCPHookEvidenceV4
		if routedDHCPOwnerDecodeV3([]byte(raw), &h) != nil || h.PID != helper {
			return 0, ErrIdentity
		}
		if h.Epoch != grant.Epoch {
			continue
		}
		if initial != 0 || h.LeaseSeconds != 71 || h.HookBootNS <= 0 || h.HookBootNS >= grant.Snapshot.DeadlineBootNS || grant.Snapshot.DeadlineBootNS-h.HookBootNS > int64(71*time.Second) {
			return 0, ErrIdentity
		}
		initial = h.HookBootNS
	}
	if initial == 0 {
		return 0, ErrIdentity
	}
	return initial, nil
}

func nativeDHCPB2ReadyV2(seconds uint32, bound nativeDHCPJobsReportV4, ready nativeDHCPB2APIReportV4, checkpoint nativeDHCPContinuityCheckpointV4, g, now int64) error {
	if ready.PID <= 1 || ready.PID != bound.PID || ready.Phase != "ready" || ready.Seconds != seconds || ready.Running != bound.Running || !reflect.DeepEqual(ready.Grant, bound.Grant) || !routedPrivateHashV4(ready.Work) || !continuityCheckpointValidV4(checkpoint) || checkpoint.AfterBootNS <= g || checkpoint.TCP.EchoBootNS > now || checkpoint.UDP.EchoBootNS > now || g <= 0 || now <= 0 || now >= g+int64(21450*time.Millisecond) {
		return ErrIdentity
	}
	return nil
}

func nativeDHCPB2WithReadyV2(seconds uint32, bound nativeDHCPJobsReportV4, ready nativeDHCPB2APIReportV4, checkpoint nativeDHCPContinuityCheckpointV4, g, now int64, action func() error) error {
	if err := nativeDHCPB2ReadyV2(seconds, bound, ready, checkpoint, g, now); err != nil {
		return err
	}
	return action()
}

func nativeDHCPB2RootV4(t *testing.T, ctx context.Context, seconds uint32, base string, namespaces [3]*os.File, supervisor *RoutedLaunchSupervisorV3, logs *nativeLogV3, bound nativeDHCPJobsReportV4, diagnostic *nativeDHCPB2DiagnosticsV4, pause *nativeDHCPB2PauseV2, stopInitial, stopDiagnostic func()) {
	t.Helper()
	defer func() {
		if t.Failed() {
			t.Logf("ANDEIVA_NATIVE_DHCP_B2_FAILURE_BUFFER_V2\n%s", logs.String())
		}
	}()
	helper, api := supervisor.PIDs()
	g0, err := nativeDHCPB2InitialHookV2(logs.String(), helper, bound.Grant)
	if err != nil {
		t.Fatal("B2 requires exact authenticated initial hook", err)
	}
	deadline := bound.Grant.Snapshot.DeadlineBootNS
	if seconds == 70 {
		deadline = g0 + int64(70*time.Second)
	}
	now, err := routedDHCPOwnerBootNowV3()
	if err != nil || deadline <= now || seconds == 71 && g0+int64(35*time.Second) >= deadline {
		t.Fatal("B2 natural renewal does not precede conservative deadline")
	}
	trial, cancelTrial := context.WithTimeout(ctx, time.Duration(deadline-now))
	defer cancelTrial()
	ctx = trial
	nativeDHCPContinuitySourceV4(t, ctx, namespaces[1])
	flow, err := startNativeDHCPContinuityV4(t, ctx, namespaces[1], namespaces[2])
	if err != nil {
		t.Fatal("B2 persistent flow startup", err)
	}
	stopShort := func() {}
	if seconds == 70 {
		stopInitial()
		stopShort = nativeDHCPB2ServerV4(t, ctx, base, namespaces[2], seconds, logs)
	}
	defer stopShort()
	if err = nativeDHCPB2SignalV4(supervisor); err != nil {
		t.Fatal("B2 flow READY", err)
	}
	readyDeadline := g0 + int64(21450*time.Millisecond)
	now, err = routedDHCPOwnerBootNowV3()
	if err != nil || now >= readyDeadline {
		t.Fatal("B2 flow/API READY deadline already missed")
	}
	readyCtx, cancelReady := context.WithTimeout(ctx, time.Duration(readyDeadline-now))
	defer cancelReady()
	initialCheckpoint, err := flow.Checkpoint(readyCtx, now)
	if err != nil {
		t.Fatal("B2 requires fresh TCP and UDP echoes before perturbation", err)
	}
	var ready nativeDHCPB2APIReportV4
	readyTick := time.NewTicker(10 * time.Millisecond)
	defer readyTick.Stop()
	for {
		var exists bool
		ready, exists, err = nativeDHCPB2ReportV4(logs.String(), api, "ready")
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			break
		}
		select {
		case <-readyTick.C:
		case <-readyCtx.Done():
			t.Fatal("B2 actual API READY did not arrive before stop target", readyCtx.Err())
		}
	}
	now, err = routedDHCPOwnerBootNowV3()
	if err != nil {
		t.Fatal("B2 READY clock unavailable")
	}
	var pauseReport *nativeDHCPPauseReportV2
	err = nativeDHCPB2WithReadyV2(seconds, bound, ready, initialCheckpoint, g0, now, func() error {
		if seconds != 71 {
			return nil
		}
		if bound.Grant.Snapshot.DeadlineBootNS-g0 < int64(43500*time.Millisecond) {
			return errors.New("B2 pause requires exact unchanged calendar due")
		}
		r, e := pause.run(ctx, g0)
		if e != nil {
			return e
		}
		pauseReport = &r
		return nil
	})
	if err != nil {
		t.Fatal("B2 READY or native pause failed without waiver", err)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var closedAt, openedAt int64
	var closedProofs []nativeDHCPB2ClosedProofV4
	closedSamples := 0
	var storeBefore [32]byte
	var recovered nativeDHCPB2APIReportV4
	var finalDiagnostic nativeDHCPB2DiagnosticStateV4
	for {
		d := diagnostic.snapshot()
		if d.err != nil || d.Ended || d.MarginCount > 1 {
			t.Fatal("B2 acquisition evidence unavailable or repeated warning", d.err, d.Ended, d.MarginCount)
		}
		var exists bool
		if ready, exists, err = nativeDHCPB2ReportV4(logs.String(), api, "ready"); err != nil {
			t.Fatal(err)
		}
		if exists && (ready.Seconds != seconds || ready.Running != bound.Running || !reflect.DeepEqual(ready.Grant, bound.Grant) || !routedPrivateHashV4(ready.Work)) {
			t.Fatal("B2 READY lost original selection")
		}
		if d.MarginBootNS > 0 && exists {
			if err = nativeDHCPB2NoProbeV4(seconds, d); err != nil {
				t.Fatal(err)
			}
			if seconds == 70 {
				for _, g := range d.Grants {
					if g.Seconds == 70 && g.BootNS+int64(35*time.Second) >= deadline {
						t.Fatal("B2 natural wait would cross conservative trial deadline")
					}
					if g.Seconds == 70 {
						break
					}
				}
			}
			if closedAt == 0 {
				if nativeDHCPB2ClosedKernelV4(ctx, namespaces[0]) == nil {
					closedAt, err = routedDHCPOwnerBootNowV3()
					if err != nil {
						t.Fatal(err)
					}
					proof, e := nativeDHCPB2ClosedProofAtV4(logs.String(), helper, closedAt, bound.Grant.Snapshot.Sequence)
					if e != nil {
						t.Fatal(e)
					}
					closedProofs = append(closedProofs, proof)
					storeBefore, err = nativeDHCPB2StoreDigestV4(base)
					if err != nil {
						t.Fatal("B2 selected-store baseline", err)
					}
					closedSamples++
				}
			} else {
				targetHooks, _, renewErr := nativeDHCPB2RenewalsV4(seconds, d)
				if renewErr != nil {
					t.Fatal("B2 lost uninterrupted natural renewal evidence", renewErr)
				}
				recovered, exists, err = nativeDHCPB2ReportV4(logs.String(), api, "recovered")
				if err != nil {
					t.Fatal(err)
				}
				if seconds == 70 && exists {
					t.Fatal("70-second evidence reopened")
				}
				if seconds == 71 && exists {
					if targetHooks < 1 || recovered.Work != ready.Work || recovered.Running != ready.Running || recovered.Grant.Epoch <= bound.Grant.Epoch || recovered.Grant.Snapshot.Sequence <= bound.Grant.Snapshot.Sequence || recovered.Grant.Snapshot.Fact().Owner != bound.Grant.Snapshot.Fact().Owner {
						t.Fatal("natural recovery replaced owner/work or reused authority")
					}
					openedAt, err = routedDHCPOwnerBootNowV3()
					if err != nil {
						t.Fatal(err)
					}
					finalDiagnostic = d
					break
				}
				if seconds == 71 && targetHooks >= 1 {
					// A safe spontaneous hook ends WAIT before the API publishes its
					// read-only Live receipt. Do not call that legitimate opening an
					// old-token leak; require the fresh correlated receipt below.
					select {
					case <-ticker.C:
					case <-ctx.Done():
						t.Fatal("natural hook did not reach verified fresh Open", ctx.Err())
					}
					continue
				}
				if err = nativeDHCPB2ClosedKernelV4(ctx, namespaces[0]); err != nil {
					t.Fatal("B2 WAIT retained token or forwarding", err)
				}
				closedSamples++
				at, e := routedDHCPOwnerBootNowV3()
				if e != nil {
					t.Fatal(e)
				}
				proof, e := nativeDHCPB2ClosedProofAtV4(logs.String(), helper, at, bound.Grant.Snapshot.Sequence)
				if e != nil || len(closedProofs) >= 256 {
					t.Fatal("bounded B2 closed proof", e)
				}
				closedProofs = append(closedProofs, proof)
				if seconds == 70 && targetHooks >= 2 { // Unsafe grant plus one actual natural renewal.
					storeAfter, e := nativeDHCPB2StoreDigestV4(base)
					if e != nil || storeBefore != storeAfter {
						t.Fatal("B2 WAIT mutated selected store/audit", e)
					}
					finalDiagnostic = d
					break
				}
			}
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("B2 did not reach required natural outcome: %v\n%s", ctx.Err(), logs.String())
		}
	}
	storeAfter, storeErr := nativeDHCPB2StoreDigestV4(base)
	if storeErr != nil || storeAfter != storeBefore {
		t.Fatal("B2 retained Work/recovery mutated selected store or appended audit", storeErr)
	}
	var checkpoint nativeDHCPContinuityCheckpointV4
	waitProof := nativeDHCPB2WaitProofV4{Enter: closedProofs[0], LastClosed: closedProofs[len(closedProofs)-1], EndBootNS: closedProofs[len(closedProofs)-1].BootNS, EndReason: "one_natural_renewal_still_closed"}
	if seconds == 71 {
		nativeDHCPJobsKernelV4(t, ctx, namespaces[0], recovered.Grant.Snapshot)
		if err = nativeDHCPB2NaturalMarginV4(logs.String(), helper, recovered.Grant, finalDiagnostic); err != nil {
			t.Fatal(err)
		}
		var naturalHook int64
		for _, line := range strings.Split(logs.String(), "\n") {
			raw, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_LEASE_HOOK_V4 ")
			if !ok {
				continue
			}
			var h nativeDHCPHookEvidenceV4
			if routedDHCPOwnerDecodeV3([]byte(raw), &h) != nil || h.PID != helper {
				t.Fatal("invalid natural hook for WAIT boundary")
			}
			if h.Epoch == recovered.Grant.Epoch {
				if naturalHook != 0 {
					t.Fatal("duplicate natural hook boundary")
				}
				naturalHook = h.HookBootNS
			}
		}
		waitProof.EndBootNS, waitProof.EndReason = naturalHook, "fresh_natural_hook_before_reopen"
		waitProof.LastClosed = nativeDHCPB2ClosedProofV4{}
		for _, p := range closedProofs {
			if p.BootNS < naturalHook {
				waitProof.LastClosed = p
			}
		}
		if waitProof.LastClosed.BootNS == 0 {
			t.Fatal("no verified closed proof before natural hook")
		}
		checkpoint, err = flow.Checkpoint(ctx, openedAt)
		if err != nil {
			t.Fatal("B2 same TCP/UDP sockets did not resume", err)
		}
	}
	traffic, err := flow.Stop()
	if err != nil || traffic.TCPAccepted != 1 || traffic.TCPDisconnects != 0 || traffic.UDPTupleChanges != 0 || traffic.UDPUniqueEchoes == 0 {
		t.Fatal("B2 persistent tuple evidence", err)
	}
	missing := 0
	for _, p := range traffic.Missing {
		if p.SentBootNS >= closedAt && (openedAt == 0 || p.SentBootNS <= openedAt) {
			missing++
		}
	}
	if missing == 0 || closedSamples < 2 || finalDiagnostic.MarginCount != 1 {
		t.Fatal("B2 closure had no real traffic/readback evidence", missing, closedSamples)
	}
	waitTraffic, waitErr := nativeDHCPB2WaitTrafficEvidenceV4(traffic, waitProof)
	if waitErr != nil {
		t.Fatalf("B2 WAIT forwarding oracle: %v evidence=%+v proof=%+v", waitErr, waitTraffic, waitProof)
	}
	now, err = routedDHCPOwnerBootNowV3()
	if err != nil || now >= deadline {
		t.Fatal("B2 retirement started after conservative trial deadline")
	}
	if err = nativeDHCPB2SignalV4(supervisor); err != nil {
		t.Fatal(err)
	}
	retired := nativeDHCPJobsWaitReportV4(t, ctx, logs, "retired")
	retiredAt, retireClockErr := routedDHCPOwnerBootNowV3()
	if retireClockErr != nil || retiredAt >= deadline {
		t.Fatal("B2 retirement exceeded conservative trial deadline")
	}
	if !routedPrivateHashV4(retired.Running) || retired.Running == bound.Running {
		t.Fatal("B2 orderly retirement failed")
	}
	nativeDHCPJobsRetiredKernelV4(t, ctx, namespaces[0])
	stopDiagnostic()
	if err = supervisor.Close(); err != nil {
		t.Fatal(err)
	}
	stopShort()
	raw, err := json.Marshal(struct {
		Seconds                   uint32                           `json:"lease_seconds"`
		Version                   int                              `json:"fixture_version"`
		InitialLease              uint32                           `json:"initial_lease_seconds"`
		NaturalRenewals           int                              `json:"natural_renewals"`
		Continuity                bool                             `json:"source_continuity"`
		ConservativeDeadline      int64                            `json:"trial_conservative_deadline_boot_ns"`
		RetiredAt                 int64                            `json:"retired_boot_ns"`
		Pause                     *nativeDHCPPauseReportV2         `json:"pause"`
		ClosedAt                  int64                            `json:"closed_verified_boot_ns"`
		OpenedAt                  int64                            `json:"recovered_observed_boot_ns"`
		ClosedSamples             int                              `json:"closed_kernel_samples"`
		Missing                   int                              `json:"udp_missing_probes_sent_while_closed"`
		InternalMarginDiagnostics int                              `json:"internal_margin_diagnostic_transitions"`
		WaitProof                 nativeDHCPB2WaitProofV4          `json:"wait_closed_proof"`
		WaitTraffic               nativeDHCPB2WaitTrafficV4        `json:"wait_traffic_oracle"`
		Checkpoint                nativeDHCPContinuityCheckpointV4 `json:"post_recovery_checkpoint"`
		Traffic                   nativeDHCPContinuityReportV4     `json:"traffic"`
	}{seconds, nativeDHCPB2VersionV2, 71, 1, true, deadline, retiredAt, pauseReport, closedAt, openedAt, closedSamples, missing, finalDiagnostic.MarginCount, waitProof, waitTraffic, checkpoint, traffic})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ANDEIVA_NATIVE_DHCP_B2_RESULT_V4 %s", raw)
	t.Log("B2 natural waiting has no 10-second cut claim. UDP observations count application datagrams; unchanged tuples and TCP connection are required. Private selected-store digest is compared only, never exported.")
	t.Log("Margin transition is an internal native diagnostic, not an administrator notification or Notification Center qualification. WAIT oracle covers fully bracketed UDP writes; boundary-crossing writes are explicitly excluded, without a wire-level/PCAP guarantee.")
}

func nativeDHCPB2NaturalMarginV4(log string, helper int, grant configpoc.RoutedDHCPGrantV3, d nativeDHCPB2DiagnosticStateV4) error {
	var hook nativeDHCPHookEvidenceV4
	found := false
	for _, line := range strings.Split(log, "\n") {
		if raw, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_LEASE_HOOK_V4 "); ok {
			var h nativeDHCPHookEvidenceV4
			if routedDHCPOwnerDecodeV3([]byte(raw), &h) != nil || h.PID != helper {
				return ErrIdentity
			}
			if h.Epoch == grant.Epoch {
				if found {
					return ErrIdentity
				}
				hook, found = h, true
			}
		}
	}
	_, natural, err := nativeDHCPB2RenewalsV4(71, d)
	if err != nil {
		return err
	}
	if !found || hook.LeaseSeconds != 71 || hook.HookBootNS <= 0 || natural.BootNS < hook.HookBootNS || grant.Snapshot.DeadlineBootNS-natural.BootNS < int64(35*time.Second) {
		return errors.New("natural 71-second hook did not retain measured 35-second margin")
	}
	return nil
}

func TestNativeDHCPB2FixedMarkerV4(t *testing.T) {
	for _, kind := range []string{"missing", "70", "71", "invalid", "writable-file", "writable-parent", "symlink", "fifo", "hardlink", "wrong-owner"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			if err := os.Chmod(base, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, nativeDHCPB2MarkerV4)
			if kind != "missing" && kind != "symlink" && kind != "fifo" {
				data := "71"
				if kind == "70" {
					data = "70"
				}
				if kind == "invalid" {
					data = "72"
				}
				if err := os.WriteFile(path, []byte(data), 0444); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0444); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "writable-file":
				_ = os.Chmod(path, 0644)
			case "writable-parent":
				_ = os.Chmod(base, 0777)
			case "symlink":
				if err := os.Symlink("/etc/passwd", path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0444); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(base, "other")); err != nil {
					t.Fatal(err)
				}
			}
			dir, err := os.Open(base)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			uid := uint32(os.Getuid())
			if kind == "wrong-owner" {
				uid ^= 1
			}
			profile, err := nativeDHCPB2ReadProfileAtV4(dir, uid)
			if kind == "missing" {
				if err != nil || profile != 0 {
					t.Fatal(profile, err)
				}
			} else if kind == "70" || kind == "71" {
				want, _ := strconv.Atoi(kind)
				if err != nil || profile != uint32(want) {
					t.Fatal(profile, err)
				}
			} else if err == nil {
				t.Fatal("untrusted marker accepted", kind, profile)
			}
		})
	}
	for _, value := range []string{"0", "071", "../70", "71\n", "120", "71 "} {
		if _, err := nativeDHCPB2ProfileValueV4(value); err == nil {
			t.Fatal("non-enum selector accepted", value)
		}
	}
}

func TestNativeDHCPB2DiagnosticsV4BoundsAndNoProbes(t *testing.T) {
	const valid = "{\"boot_ns\":10,\"stage\":\"event\",\"detail\":\"BOUND\",\"lease_seconds\":71}\n{\"boot_ns\":20,\"stage\":\"early_margin_closed\",\"detail\":\"early_dispatch_late\"}\n{\"boot_ns\":56,\"stage\":\"event\",\"detail\":\"RENEW\",\"lease_seconds\":71}\n"
	var d nativeDHCPB2DiagnosticsV4
	d.observe([]byte(valid))
	state := d.snapshot()
	if state.err != nil || state.MarginCount != 1 || len(state.Grants) != 2 || nativeDHCPB2NoProbeV4(71, state) != nil {
		t.Fatal("valid bounded observation rejected", state)
	}
	state.Signals = append(state.Signals, 60)
	if nativeDHCPB2NoProbeV4(71, state) != nil || nativeDHCPB2NoProbeV4(70, state) == nil {
		t.Fatal("ordinary B1 after recovery confused with closed probe")
	}
	state.Signals = []int64{10, 30}
	if nativeDHCPB2NoProbeV4(71, state) == nil {
		t.Fatal("signal inside WAIT accepted")
	}
	state.Signals = []int64{9, 10}
	if nativeDHCPB2NoProbeV4(71, state) == nil {
		t.Fatal("pre-closure signal burst accepted")
	}
	for _, bad := range []string{valid + `{"boot_ns":60,"stage":"truncated"}`, valid + `{"boot_ns":60,"stage":"early_margin_closed"}`, valid + `{"boot_ns":60,"stage":"event","unknown":1}`, valid + `{"boot_ns":60,"boot_ns":61,"stage":"event"}`, strings.Repeat("x", (64<<10)+1)} {
		var invalid nativeDHCPB2DiagnosticsV4
		invalid.observe([]byte(bad))
		invalid.observe([]byte(valid))
		if invalid.snapshot().err == nil {
			t.Fatal("malformed/truncated diagnostics recovered silently")
		}
	}
}

func TestNativeDHCPB2DiagnosticsV4RejectsReacquisitionAsNaturalRenewal(t *testing.T) {
	const prefix = "{\"boot_ns\":29004466547066,\"stage\":\"early_signal\"}\n{\"boot_ns\":29004503224772,\"stage\":\"early_margin_closed\",\"detail\":\"early_short_lease\"}\n{\"boot_ns\":29004503272672,\"stage\":\"event\",\"detail\":\"RENEW\",\"lease_seconds\":70}\n"
	for _, reason := range []string{"EXPIRE", "FAIL", "NOCARRIER", "BOUND", "REBOOT", "REBIND"} {
		t.Run(reason, func(t *testing.T) {
			// The EXPIRE/BOUND/RENEW timestamps reproduce the false PASS from
			// the 186.64-second native run; reacquisition is not renewal.
			middle := fmt.Sprintf("{\"boot_ns\":29028932800510,\"stage\":\"event\",\"detail\":%q}\n", reason)
			if reason == "BOUND" || reason == "REBOOT" || reason == "REBIND" {
				middle = fmt.Sprintf("{\"boot_ns\":29028932800510,\"stage\":\"event\",\"detail\":%q,\"lease_seconds\":70}\n", reason)
			}
			raw := prefix + middle + "{\"boot_ns\":29034253784920,\"stage\":\"event\",\"detail\":\"BOUND\",\"lease_seconds\":70}\n{\"boot_ns\":29100371869773,\"stage\":\"event\",\"detail\":\"RENEW\",\"lease_seconds\":70}\n"
			var d nativeDHCPB2DiagnosticsV4
			d.observe([]byte(raw))
			if nativeDHCPB2NoProbeV4(70, d.snapshot()) == nil {
				t.Fatal("interrupted/reacquired lease accepted as continuous natural renewal")
			}
		})
	}
	var valid nativeDHCPB2DiagnosticsV4
	valid.observe([]byte("{\"boot_ns\":28958466604033,\"stage\":\"event\",\"detail\":\"BOUND\",\"lease_seconds\":120}\n" + prefix + "{\"boot_ns\":29039503272672,\"stage\":\"event\",\"detail\":\"RENEW\",\"lease_seconds\":70}\n{\"boot_ns\":29074503272672,\"stage\":\"event\",\"detail\":\"RENEW\",\"lease_seconds\":70}\n"))
	state := valid.snapshot()
	count, natural, err := nativeDHCPB2RenewalsV4(70, state)
	if nativeDHCPB2NoProbeV4(70, state) != nil || err != nil || count != 3 || natural.Reason != "RENEW" || natural.BootNS != 29039503272672 {
		t.Fatal("two uninterrupted natural renewals rejected")
	}
	for _, reason := range []string{"EXPIRE", "FAIL", "NOCARRIER"} {
		var interrupted nativeDHCPB2DiagnosticsV4
		interrupted.observe([]byte(prefix + fmt.Sprintf("{\"boot_ns\":29028932800510,\"stage\":\"event\",\"detail\":%q}\n", reason)))
		// Even a later complete-looking snapshot cannot silently forget the
		// invalidating event already observed by the collector.
		interrupted.observe([]byte(prefix))
		if interrupted.snapshot().err == nil || nativeDHCPB2NoProbeV4(70, interrupted.snapshot()) == nil {
			t.Fatal("lease continuity loss was not latched", reason)
		}
	}
	for _, mutate := range []func(*nativeDHCPB2DiagnosticStateV4){
		func(s *nativeDHCPB2DiagnosticStateV4) { s.Grants[2].Reason = "BOUND" },
		func(s *nativeDHCPB2DiagnosticStateV4) { s.Grants[2].Seconds = 71 },
		func(s *nativeDHCPB2DiagnosticStateV4) { s.Grants[2].BootNS = s.Grants[1].BootNS },
		func(s *nativeDHCPB2DiagnosticStateV4) { s.Grants[2].Seconds = 0 },
		func(s *nativeDHCPB2DiagnosticStateV4) { s.Ended = true },
	} {
		invalid := valid.snapshot()
		mutate(&invalid)
		if _, _, err := nativeDHCPB2RenewalsV4(70, invalid); err == nil {
			t.Fatal("inconsistent renewal evidence accepted")
		}
	}
}

func TestNativeDHCPB2ClosedSetsV4RejectResidualAuthority(t *testing.T) {
	const valid = `{"nftables":[{"set":{"family":"inet","table":"andeiva_lease_gate","name":"enabled"}},{"set":{"family":"inet","table":"andeiva_lease_gate","name":"live","elem":[]}}]}`
	if err := nativeDHCPB2ClosedSetsV4([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(valid, `"elem":[]`, `"elem":["wan0"]`, 1), strings.Replace(valid, `"name":"live"`, `"name":"enabled"`, 1), strings.Replace(valid, `"family":"inet"`, `"family":"ip"`, 1), strings.Replace(valid, `"name":"live"`, `"name":"other"`, 1), strings.Replace(valid, `"elem":[]`, `"elem":[],"elem":[]`, 1), `{"nftables":[]}`} {
		if nativeDHCPB2ClosedSetsV4([]byte(bad)) == nil {
			t.Fatal("missing/uncertain/nonempty token proof accepted")
		}
	}
}

func TestNativeDHCPB2StoreDigestV4DetectsGrowthAndRejectsLinks(t *testing.T) {
	base := t.TempDir()
	store := filepath.Join(base, "store")
	if err := os.Mkdir(store, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(store, "protected-audit-fixture")
	if err := os.WriteFile(file, []byte("one\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := nativeDHCPB2StoreDigestV4(base)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, []byte("one\ntwo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := nativeDHCPB2StoreDigestV4(base)
	if err != nil || before == after {
		t.Fatal("store/audit growth invisible", err)
	}
	if err = os.Symlink(file, filepath.Join(store, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err = nativeDHCPB2StoreDigestV4(base); err == nil {
		t.Fatal("linked store input accepted")
	}
}

func TestNativeDHCPB2NaturalMarginV4RequiresFreshMeasuredAuthority(t *testing.T) {
	grant := configpoc.RoutedDHCPGrantV3{Epoch: 3}
	grant.Snapshot.DeadlineBootNS = int64(90 * time.Second)
	hook := nativeDHCPHookEvidenceV4{PID: 123, Epoch: 3, HookBootNS: int64(54 * time.Second), LeaseSeconds: 71}
	raw, _ := json.Marshal(hook)
	log := "ANDEIVA_NATIVE_LEASE_HOOK_V4 " + string(raw) + "\n"
	d := nativeDHCPB2DiagnosticStateV4{MarginBootNS: int64(21 * time.Second), MarginCount: 1, Grants: []nativeDHCPB2GrantV4{{int64(20 * time.Second), 71, "BOUND"}, {int64(55 * time.Second), 71, "RENEW"}}}
	if err := nativeDHCPB2NaturalMarginV4(log, 123, grant, d); err != nil {
		t.Fatal("measured35s boundary rejected", err)
	}
	grant.Snapshot.DeadlineBootNS--
	if nativeDHCPB2NaturalMarginV4(log, 123, grant, d) == nil {
		t.Fatal("insufficient post-acceptance margin accepted")
	}
	grant.Snapshot.DeadlineBootNS++
	for _, bad := range []string{log + log, strings.Replace(log, `"pid":123`, `"pid":456`, 1), strings.Replace(log, `"epoch":3`, `"epoch":2`, 1), strings.Replace(log, `"lease_seconds":71`, `"lease_seconds":70`, 1)} {
		if nativeDHCPB2NaturalMarginV4(bad, 123, grant, d) == nil {
			t.Fatal("ambiguous/foreign/notfresh hook accepted")
		}
	}
}

func TestNativeDHCPB2InitialHookV2RejectsDiagnosticClockOrForeignEpoch(t *testing.T) {
	grant := configpoc.RoutedDHCPGrantV3{Epoch: 1}
	grant.Snapshot.Sequence = 1
	grant.Snapshot.DeadlineBootNS = int64(80 * time.Second)
	h := nativeDHCPHookEvidenceV4{PID: 123, Epoch: 1, HookBootNS: int64(20 * time.Second), LeaseSeconds: 71}
	raw, _ := json.Marshal(h)
	valid := "ANDEIVA_NATIVE_LEASE_HOOK_V4 " + string(raw) + "\n"
	if got, err := nativeDHCPB2InitialHookV2(valid, 123, grant); err != nil || got != h.HookBootNS {
		t.Fatal("exact initial hook rejected", got, err)
	}
	for _, bad := range []string{"", valid + valid, strings.Replace(valid, `"pid":123`, `"pid":456`, 1), strings.Replace(valid, `"epoch":1`, `"epoch":2`, 1), strings.Replace(valid, `"lease_seconds":71`, `"lease_seconds":120`, 1), strings.Replace(valid, `"hook_boot_ns":20000000000`, `"hook_boot_ns":80000000000`, 1), "ANDEIVA_NATIVE_DHCP_OWNER {\"boot_ns\":20000000000,\"stage\":\"event\",\"detail\":\"BOUND\",\"lease_seconds\":71}\n"} {
		if _, err := nativeDHCPB2InitialHookV2(bad, 123, grant); err == nil {
			t.Fatal("missing/ambiguous/foreign or diagnostic-write clock accepted")
		}
	}
}

func TestNativeDHCPB2FreshLiveV2DoesNotRetryFailureOrEmitRecovery(t *testing.T) {
	calls, emits := 0, 0
	want := errors.New("first fresh Live failed")
	done, err := nativeDHCPB2FreshLiveV2(func() (bool, error) {
		calls++
		if calls == 1 {
			return true, want
		}
		return true, nil
	}, func() error { emits++; return nil })
	if done || !errors.Is(err, want) || calls != 1 || emits != 0 {
		t.Fatal("fresh failure retried or emitted recovered", done, err, calls, emits)
	}
	done, err = nativeDHCPB2FreshLiveV2(func() (bool, error) { return true, nil }, func() error { emits++; return nil })
	if !done || err != nil || emits != 1 {
		t.Fatal("single healthy receipt failed", done, err, emits)
	}
}

func TestNativeDHCPB2ReadyV2LateOrUnprovenReadyNeverPauses(t *testing.T) {
	g := int64(time.Second)
	now := g + int64(20*time.Second)
	bound := nativeDHCPJobsReportV4{PID: 123, Running: strings.Repeat("a", 64), Grant: configpoc.RoutedDHCPGrantV3{Epoch: 1}}
	ready := nativeDHCPB2APIReportV4{PID: 123, Phase: "ready", Seconds: 71, Work: strings.Repeat("b", 64), Running: bound.Running, Grant: bound.Grant}
	cp := nativeDHCPContinuityCheckpointV4{ID: 1, AfterBootNS: g + 1, TCP: nativeDHCPContinuitySampleV4{1, g + 2, g + 3}, UDP: nativeDHCPContinuitySampleV4{1, g + 2, g + 3}}
	calls := 0
	if err := nativeDHCPB2WithReadyV2(71, bound, ready, cp, g, now, func() error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatal("valid scoped ready rejected", err, calls)
	}
	for _, mutate := range []func(*nativeDHCPB2APIReportV4, *nativeDHCPContinuityCheckpointV4, *int64){
		func(_ *nativeDHCPB2APIReportV4, _ *nativeDHCPContinuityCheckpointV4, now *int64) {
			*now = g + int64(21450*time.Millisecond)
		},
		func(r *nativeDHCPB2APIReportV4, _ *nativeDHCPContinuityCheckpointV4, _ *int64) { r.PID++ },
		func(r *nativeDHCPB2APIReportV4, _ *nativeDHCPContinuityCheckpointV4, _ *int64) { r.Phase = "other" },
		func(r *nativeDHCPB2APIReportV4, _ *nativeDHCPContinuityCheckpointV4, _ *int64) { r.Work = "" },
		func(r *nativeDHCPB2APIReportV4, _ *nativeDHCPContinuityCheckpointV4, _ *int64) { r.Grant.Epoch++ },
		func(_ *nativeDHCPB2APIReportV4, c *nativeDHCPContinuityCheckpointV4, _ *int64) { c.TCP.Sequence = 0 },
		func(_ *nativeDHCPB2APIReportV4, c *nativeDHCPContinuityCheckpointV4, _ *int64) { c.UDP.Sequence = 0 },
		func(_ *nativeDHCPB2APIReportV4, c *nativeDHCPContinuityCheckpointV4, _ *int64) { c.AfterBootNS = g - 1 },
	} {
		r, c, n := ready, cp, now
		mutate(&r, &c, &n)
		signals := 0
		if err := nativeDHCPB2WithReadyV2(71, bound, r, c, g, n, func() error { signals++; return nil }); err == nil || signals != 0 {
			t.Fatal("late/unproven READY triggered pause", err, signals)
		}
	}
}

func TestNativeDHCPB2HarnessV4RejectsWrongOrMissingExecution(t *testing.T) {
	script := filepath.Join("..", "..", "packaging", "preview", "tests", "dhcp-b2-native.sh")
	check := func(profile, log string) bool {
		t.Helper()
		path := filepath.Join(t.TempDir(), "native.log")
		if err := os.WriteFile(path, []byte(log), 0600); err != nil {
			t.Fatal(err)
		}
		return exec.Command("/usr/bin/bash", script, "--check-log", profile, path).Run() == nil
	}
	makeLog := func(profile string) string {
		name := "TestNativeRoutedDHCPB2Natural" + profile + "V4"
		return "=== RUN   " + name + "\n    native.go:1: ANDEIVA_NATIVE_DHCP_B2_RESULT_V4 {\"lease_seconds\":" + profile + ",\"fixture_version\":2,\"initial_lease_seconds\":71,\"natural_renewals\":1,\"source_continuity\":true,\"internal_margin_diagnostic_transitions\":1,\"wait_closed_proof\":{},\"wait_traffic_oracle\":{\"writes_fully_inside_wait\":2,\"sink_receipts_of_fully_bounded_writes\":0,\"boundary\":0}}\n--- PASS: " + name + " (96.77s)\nPASS\nANDEIVA_NATIVE_DHCP_JOBS_CLEANUP_OK\n"
	}
	for _, profile := range []string{"70", "71"} {
		if !check(profile, makeLog(profile)) {
			t.Fatal("exact B2 execution rejected", profile)
		}
	}
	valid := makeLog("70")
	for name, bad := range map[string]string{
		"exit_zero_stub":             "",
		"old_binary_no_tests":        "testing: warning: no tests to run\nPASS\nANDEIVA_NATIVE_DHCP_JOBS_CLEANUP_OK\n",
		"wrong_test_name":            strings.ReplaceAll(valid, "TestNativeRoutedDHCPB2Natural70V4", "TestNativeRoutedDHCPEarlyRenewalV4"),
		"wrong_result_lease":         strings.Replace(valid, `"lease_seconds":70`, `"lease_seconds":71`, 1),
		"old_fixture_version":        strings.Replace(valid, `"fixture_version":2,`, "", 1),
		"wrong_fixture_version":      strings.Replace(valid, `"fixture_version":2`, `"fixture_version":1`, 1),
		"old_initial_lease":          strings.Replace(valid, `"initial_lease_seconds":71`, `"initial_lease_seconds":120`, 1),
		"no_natural_renewal":         strings.Replace(valid, `"natural_renewals":1`, `"natural_renewals":0`, 1),
		"lost_source_continuity":     strings.Replace(valid, `"source_continuity":true`, `"source_continuity":false`, 1),
		"old_b2_without_wait_oracle": strings.Replace(valid, "wait_traffic_oracle", "old_no_oracle", 1),
		"leaked_sink_receipt":        strings.Replace(valid, `"sink_receipts_of_fully_bounded_writes":0`, `"sink_receipts_of_fully_bounded_writes":1`, 1),
		"missing_result":             strings.Replace(valid, "ANDEIVA_NATIVE_DHCP_B2_RESULT_V4", "other-result", 1),
		"duplicate_result":           valid + "ANDEIVA_NATIVE_DHCP_B2_RESULT_V4 {\"lease_seconds\":70,\"extra\":true}\n",
		"skip":                       valid + "\t--- SKIP: nested (0.00s)\n",
		"failed_child":               valid + "--- FAIL: child (0.00s)\n",
		"no_cleanup":                 strings.Replace(valid, "ANDEIVA_NATIVE_DHCP_JOBS_CLEANUP_OK", "cleanup missing", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if check("70", bad) {
				t.Fatal("false-positive B2 run accepted")
			}
		})
	}
}

func TestNativeDHCPB2WaitTrafficV4RejectsOneInteriorLeakDespiteLoss(t *testing.T) {
	proof := nativeDHCPB2WaitProofV4{Enter: nativeDHCPB2ClosedProofV4{100, 1}, LastClosed: nativeDHCPB2ClosedProofV4{180, 1}, EndBootNS: 200, EndReason: "fresh_natural_hook_before_reopen"}
	var traffic nativeDHCPContinuityReportV4
	for i, span := range [][2]int64{{50, 60}, {110, 111}, {130, 131}, {190, 210}, {220, 221}} {
		seq := uint64(i + 1)
		traffic.UDPSentSet.add(seq)
		traffic.UDPSendStartBootNS[seq], traffic.UDPSendEndBootNS[seq] = span[0], span[1]
	}
	for _, seq := range []uint64{1, 4, 5} {
		traffic.UDPSinkReceivedSet.add(seq)
	}
	traffic.UDPMissingEchoes = 2
	result, err := nativeDHCPB2WaitTrafficEvidenceV4(traffic, proof)
	if err != nil || result.FullyBounded != 2 || result.SinkReceipts != 0 || result.PriorExcluded != 1 || result.BoundaryAmbiguous != 1 {
		t.Fatal("pre-WAIT queue or explicitly crossing boundary misclassified", result, err)
	}
	// A request may reach the sink while its echo is lost. Missing echoes alone
	// remain positive, but that one forbidden sink receipt MUST fail the oracle.
	traffic.UDPSinkReceivedSet.add(2)
	result, err = nativeDHCPB2WaitTrafficEvidenceV4(traffic, proof)
	if err == nil || result.SinkReceipts != 1 || traffic.UDPMissingEchoes == 0 {
		t.Fatal("one leaked datagram hidden by other UDP losses", result, err)
	}
	traffic.UDPSinkReceivedSet = continuitySetV4{}
	proof.LastClosed.Sequence = 2
	if _, err = nativeDHCPB2WaitTrafficEvidenceV4(traffic, proof); err == nil {
		t.Fatal("changed fence accepted as same closed WAIT")
	}
}

func TestNativeDHCPB2WaitProofV4RejectsUnprovenOrReopenedState(t *testing.T) {
	const closed = "ANDEIVA_NATIVE_LEASE_PHASE_V4 {\"pid\":123,\"boot_ns\":90,\"phase\":\"closed\",\"sequence\":1}\n"
	if p, err := nativeDHCPB2ClosedProofAtV4(closed, 123, 100, 1); err != nil || p.Sequence != 1 || p.BootNS != 100 {
		t.Fatal(p, err)
	}
	for _, bad := range []string{"", strings.Replace(closed, `"pid":123`, `"pid":456`, 1), closed + "ANDEIVA_NATIVE_LEASE_PHASE_V4 {\"pid\":123,\"boot_ns\":95,\"phase\":\"opened\",\"sequence\":0}\n", strings.Replace(closed, `"sequence":1`, `"sequence":2`, 1)} {
		if _, err := nativeDHCPB2ClosedProofAtV4(bad, 123, 100, 1); err == nil {
			t.Fatal("unproven/foreign/open state accepted")
		}
	}
}

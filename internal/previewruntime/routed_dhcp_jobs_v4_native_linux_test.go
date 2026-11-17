//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/dhcpclient"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"github.com/AsterG/andeiva/internal/routednft"
	"golang.org/x/sys/unix"
)

// Explicit root laboratory only. The packet server is a test peer; acquisition,
// private FD15/SCM transport, selected store, helper and kernel executors are real.
func TestNativeRoutedDHCPJobsV4(t *testing.T) {
	nativeRunRoutedDHCPJobsV4(t, false)
}

// The combined early-renewal/API-restart trial remains failed evidence. This
// profile qualifies continuity and orderly retirement only, never API restart.
func TestNativeRoutedDHCPEarlyRenewalV4(t *testing.T) {
	nativeRunRoutedDHCPJobsV4(t, true)
}

const nativeDHCPEarlyRenewalSamplesV4 = 10

func nativeRunRoutedDHCPJobsV4(t *testing.T, early bool) {
	t.Helper()
	if os.Getenv("ANDEIVA_NATIVE_DHCP_JOBS_V4") != "1" {
		t.Skip("requires authorized isolated root laboratory harness")
	}
	if os.Getenv("CI") != "" || os.Getuid() != 0 || os.Geteuid() != 0 || routedDHCPOwnerCgroupV3() != nil {
		t.Fatal("root laboratory only")
	}
	budget := 210 * time.Second
	if early {
		budget = 700 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	self, e := os.Executable()
	if e != nil || trustedRoutedExecutableV3(self) != nil {
		t.Fatal("untrusted native fixture binary")
	}
	var namespaces [3]*os.File
	for i := range namespaces {
		fd := i + 3
		var fs unix.Statfs_t
		kind, e := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		if e != nil || kind != unix.CLONE_NEWNET || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC {
			t.Fatal("invalid inherited namespace")
		}
		namespaces[i] = os.NewFile(uintptr(fd), "native-netns")
		unix.CloseOnExec(fd)
		defer namespaces[i].Close()
	}
	host, e := os.Open("/proc/self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	defer host.Close()
	base, e := os.MkdirTemp(filepath.Dir(self), "state-")
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error("native resource cleanup", err)
		}
	}()
	if e = os.Chmod(base, 0755); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"store", "admission", "plan", "emergency"} {
		path := filepath.Join(base, name)
		if e = os.Mkdir(path, 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.Chown(path, int(nativeIdentitiesV3.APIUID), nativeReaderGIDV3); e != nil {
			t.Fatal(e)
		}
	}
	sockets := filepath.Join(base, "sockets")
	if e = os.Mkdir(sockets, 0750); e != nil {
		t.Fatal(e)
	}
	// The production manager applies the exact directory mode after creation;
	// the fixture must also work under the service's restrictive UMask0077.
	if e = os.Chmod(sockets, 0750); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(sockets, int(nativeIdentitiesV3.HelperUID), int(nativeIdentitiesV3.IPCGID)); e != nil {
		t.Fatal(e)
	}
	var secret [32]byte
	if _, e = rand.Read(secret[:]); e != nil {
		t.Fatal(e)
	}
	credential := hex.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(credential))
	subject, e := configpoc.NewSubjectIDV2()
	if e != nil {
		t.Fatal(e)
	}
	auth := nativeAuthV3{Account: adminauth.Account{Username: "native-operator", Role: "admin", SubjectID: subject, CredentialRevision: hex.EncodeToString(digest[:]), CredentialSHA256: hex.EncodeToString(digest[:])}, Credential: credential}
	data, e := json.Marshal(auth)
	if e != nil {
		t.Fatal(e)
	}
	for name, content := range map[string][]byte{"api-auth.json": data, "api-audit.jsonl": nil, "seed-profiles.json": nil} {
		path := filepath.Join(base, name)
		if e = os.WriteFile(path, content, 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.Chown(path, int(nativeIdentitiesV3.APIUID), int(nativeIdentitiesV3.APIGID)); e != nil {
			t.Fatal(e)
		}
	}
	baseFD, e := os.Open(base)
	if e != nil {
		t.Fatal(e)
	}
	seed := exec.CommandContext(ctx, "/usr/bin/setpriv", "--reuid=62001", "--regid=62001", "--groups=62004", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", self, nativeSeedRoleV3)
	seed.ExtraFiles = []*os.File{baseFD}
	seed.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	seed.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	runtime.LockOSThread()
	output, e := seed.CombinedOutput()
	runtime.UnlockOSThread()
	_ = baseFD.Close()
	if e != nil {
		t.Fatalf("offline seed failed: %v %s", e, output)
	}
	data, e = os.ReadFile(filepath.Join(base, "seed-profiles.json"))
	if e != nil {
		t.Fatal(e)
	}
	var prepared nativeSeedResultV3
	if e = json.Unmarshal(data, &prepared); e != nil {
		t.Fatal(e)
	}
	var roots [4]*os.Root
	for i, name := range []string{"store", "admission", "plan", "emergency"} {
		roots[i], e = os.OpenRoot(filepath.Join(base, name))
		if e != nil {
			t.Fatal(e)
		}
		defer roots[i].Close()
	}
	directory, e := os.OpenRoot(sockets)
	if e != nil {
		t.Fatal(e)
	}
	defer directory.Close()
	inode := func(f *os.File) uint64 {
		info, e := f.Stat()
		if e != nil {
			t.Fatal(e)
		}
		return info.Sys().(*syscall.Stat_t).Ino
	}
	bootBytes, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		t.Fatal(e)
	}
	boot, e := canonicalBoot(bootBytes)
	if e != nil {
		t.Fatal(e)
	}
	var run [16]byte
	if _, e = rand.Read(run[:]); e != nil {
		t.Fatal(e)
	}
	metadata := Metadata{SchemaVersion: 1, RunID: hex.EncodeToString(run[:]), BootID: boot, HostNamespace: inode(host), GatewayNamespace: inode(namespaces[0]), SourceNamespace: inode(namespaces[1]), SinkNamespace: inode(namespaces[2])}
	if metadata.ValidateRouted() != nil {
		t.Fatal("three distinct namespace pins required")
	}
	resource := func(i int) RoutedReaderRootV3 {
		v := RoutedReaderRootV3{Root: roots[i], Access: prepared.Access[i]}
		if i > 0 {
			v.Profile = prepared.Profiles[i-1]
		}
		return v
	}
	var logs nativeLogV3
	if early {
		logs.limit = 512 << 10
	}
	var private *os.Root
	{
		path := filepath.Join(base, "integrity")
		if e = os.Mkdir(path, 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.Chown(path, int(nativeIdentitiesV3.HelperUID), int(nativeIdentitiesV3.IPCGID)); e != nil {
			t.Fatal(e)
		}
		private, e = os.OpenRoot(path)
		if e != nil {
			t.Fatal(e)
		}
		defer private.Close()
		if e = PrepareRoutedIntegrityLaunchV3(ctx, nativeIdentitiesV3, private, &logs); e != nil {
			t.Fatalf("explicit capless preparation failed: %v %s", e, logs.String())
		}
		original, e := private.ReadFile(routedIntegrityFenceNameV3)
		if e != nil || len(original) != 4096 || original[routedIntegrityFenceStateV3] != 0 {
			t.Fatal("invalid prepared marker", e)
		}
		if e = PrepareRoutedIntegrityLaunchV3(ctx, nativeIdentitiesV3, private, io.Discard); e == nil {
			t.Fatal("installer reset an existing marker")
		}
		after, e := private.ReadFile(routedIntegrityFenceNameV3)
		if e != nil || !bytes.Equal(original, after) {
			t.Fatal("failed preparation changed marker", e)
		}
	}
	stopServer := nativeDHCPJobsServerV4(t, ctx, base, namespaces[2], &logs)
	defer stopServer()
	stopDiagnostic := nativeDHCPJobsCollectV4(t, ctx, metadata)
	defer stopDiagnostic()
	supervisor, e := StartRoutedLaunchV3(ctx, RoutedLaunchResourcesV3{DHCPJobs: true, DHCPRenewalV4: early, Metadata: metadata, Identities: nativeIdentitiesV3, Gateway: namespaces[0], Host: host, Directory: directory, IntegrityRoot: private, Store: resource(0), Admission: resource(1), Plan: resource(2), Emergency: resource(3), Budget: nativeSelectionBudgetV3()}, &logs)
	if e != nil {
		t.Fatalf("native DHCP launch failed: %v\n%s", e, logs.String())
	}
	defer func() {
		trace, closeErr := nativeDHCPJobsCloseTraceV4(&logs, supervisor.Close)
		if trace != "" {
			t.Log(trace)
		}
		if closeErr != nil {
			t.Error("native supervisor close failed")
		}
	}()
	defer stopDiagnostic() // Collect before supervisor teardown on failure.
	helper, api := supervisor.PIDs()
	nativeDHCPJobsPrivilegesV4(t, helper, api, metadata, &logs)
	bound := nativeDHCPJobsWaitReportV4(t, ctx, &logs, "bound")
	nativeDHCPJobsKernelV4(t, ctx, namespaces[0], bound.Grant.Snapshot)
	var earlyCuts []nativeDHCPCutV4
	var earlyAdoptions []nativeDHCPAdoptionEvidenceV4
	if early {
		nativeDHCPContinuitySourceV4(t, ctx, namespaces[1])
		flow, e := startNativeDHCPContinuityProfileV4(t, ctx, namespaces[1], namespaces[2], continuityTenRenewalsV4)
		if e != nil {
			t.Fatal("start persistent TCP/UDP", e)
		}
		var readyBoot unix.Timespec
		if e = unix.ClockGettime(unix.CLOCK_BOOTTIME, &readyBoot); e != nil {
			t.Fatal(e)
		}
		// Test-only synchronization on the retained API process, not DHCP authority.
		supervisor.mu.Lock()
		e = supervisor.api.cmd.Process.Signal(syscall.SIGUSR2)
		supervisor.mu.Unlock()
		if e != nil {
			t.Fatal("acknowledge persistent flow readiness", e)
		}
		renewed := nativeDHCPJobsWaitReportV4(t, ctx, &logs, "renewed")
		if renewed.Grant.Epoch <= bound.Grant.Epoch || renewed.Grant.Snapshot.DeadlineBootNS <= bound.Grant.Snapshot.DeadlineBootNS || renewed.Grant.Snapshot.Fact().Owner != bound.Grant.Snapshot.Fact().Owner || renewed.Running != bound.Running {
			t.Fatal("renewal reused an epoch/deadline or replaced owner/policy")
		}
		nativeDHCPJobsKernelV4(t, ctx, namespaces[0], renewed.Grant.Snapshot)
		var afterRenewals unix.Timespec
		if e = unix.ClockGettime(unix.CLOCK_BOOTTIME, &afterRenewals); e != nil {
			t.Fatal(e)
		}
		checkpoint, e := flow.Checkpoint(ctx, afterRenewals.Nano())
		if e != nil {
			t.Fatal("same TCP/UDP sockets did not progress after ten renewals", e)
		}
		traffic, e := flow.Stop()
		if e != nil || traffic.TCPAccepted != 1 || traffic.TCPDisconnects != 0 || traffic.UDPTupleChanges != 0 || traffic.UDPInvalid != 0 || traffic.UDPSent == 0 || traffic.UDPUniqueEchoes == 0 {
			t.Fatalf("persistent flow evidence failed: %v %+v", e, traffic)
		}
		cuts, e := nativeDHCPCutsV4(logs.String(), helper, readyBoot.Nano())
		if e != nil || len(cuts) != nativeDHCPEarlyRenewalSamplesV4 {
			t.Fatalf("ten verified post-READY closed/open renewal intervals required: %v %+v\n%s", e, cuts, logs.String())
		}
		adoptions, e := nativeDHCPAdoptionsV4(logs.String(), helper, api, readyBoot.Nano(), cuts)
		if e != nil {
			t.Fatal("authenticated hook-to-open evidence", e)
		}
		nativeDHCPReportAdoptionsV4(t, adoptions)
		nativeDHCPRenewalEvidenceV4(t, cuts, checkpoint, traffic)
		nativeDHCPReportPhasesV4(t, logs.String(), helper, cuts)
		earlyCuts = cuts
		earlyAdoptions = adoptions
		// Permit retirement only after the parent has collected the flow evidence.
		supervisor.mu.Lock()
		e = supervisor.api.cmd.Process.Signal(syscall.SIGUSR2)
		supervisor.mu.Unlock()
		if e != nil {
			t.Fatal("acknowledge persistent flow stopped", e)
		}
	} else {
		renewed := nativeDHCPJobsWaitReportV4(t, ctx, &logs, "renewed")
		if renewed.Grant.Epoch <= bound.Grant.Epoch || renewed.Grant.Snapshot.DeadlineBootNS <= bound.Grant.Snapshot.DeadlineBootNS || renewed.Grant.Snapshot.Fact().Owner != bound.Grant.Snapshot.Fact().Owner || renewed.Running != bound.Running {
			t.Fatal("natural renewal reused authority or replaced owner/policy")
		}
		nativeDHCPJobsKernelV4(t, ctx, namespaces[0], renewed.Grant.Snapshot)
		if e = supervisor.RestartAPI(ctx); e != nil {
			t.Fatalf("API restart failed: %v\n%s", e, logs.String())
		}
		h2, a2 := supervisor.PIDs()
		if helper != h2 || api == a2 {
			t.Fatal("API restart replaced helper or reused API PID")
		}
		nativeDHCPJobsPrivilegesV4(t, h2, a2, metadata, &logs)
		restarted := nativeDHCPJobsWaitReportV4(t, ctx, &logs, "restarted")
		if restarted.Running != bound.Running || restarted.Grant.Snapshot.Fact().Owner != bound.Grant.Snapshot.Fact().Owner || restarted.Grant.Epoch < renewed.Grant.Epoch {
			t.Fatal("API restart lost selected policy or real producer incarnation")
		}
		nativeDHCPJobsWaitReportV4(t, ctx, &logs, "rollback-fenced")
	}
	retired := nativeDHCPJobsWaitReportV4(t, ctx, &logs, "retired")
	if !routedPrivateHashV4(retired.Running) || retired.Running == bound.Running {
		t.Fatal("retirement did not restore NoNetwork")
	}
	nativeDHCPJobsRetiredKernelV4(t, ctx, namespaces[0])
	stopDiagnostic()
	if e = supervisor.Close(); e != nil {
		t.Fatal("grouped close", e)
	}
	stopServer()
	if strings.Contains(logs.String(), "native role failed:") {
		t.Fatalf("child failure: %s", logs.String())
	}
	if !nativeDHCPEvidenceLogValidV4(logs.String()) {
		t.Fatal("native log truncated or exceeded its bounded capture")
	}
	if early {
		if e := nativeDHCPEarlyBudgetsV4(earlyCuts, earlyAdoptions); e != nil {
			t.Fatal(e)
		}
		t.Log("B1+C: same TCP connection and UDP socket across ten post-READY renewals with nominal 100ms probe interval and orderly NoNetwork retirement; provisional Alpha cut/adoption maxima are 10s/12s; API restart is not qualified")
	} else {
		t.Log("Legacy: natural renewal, retained-helper API restart, active-work rollback refusal and orderly NoNetwork retirement")
	}
}

// udhcpd is only a test packet peer. The child joins the inherited WAN pin;
// no name/PID from the environment chooses a namespace or signal target.
func nativeDHCPJobsServerV4(t *testing.T, ctx context.Context, base string, wan *os.File, logs io.Writer) func() {
	t.Helper()
	if trustedRoutedExecutableV3("/usr/bin/busybox") != nil {
		t.Fatal("trusted busybox udhcpd test dependency missing")
	}
	const leaseSeconds = 120
	conf := fmt.Sprintf("start 198.18.1.10\nend 198.18.1.10\ninterface sink0\nmax_leases 1\nmin_lease 60\nlease_file %s\npidfile %s\nopt subnet 255.255.255.0\nopt router 198.18.1.1\nopt lease %d\n", filepath.Join(base, "test-server.leases"), filepath.Join(base, "test-server.pid"), leaseSeconds)
	path := filepath.Join(base, "test-server.conf")
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
		// Linux binds Pdeathsig to the creating thread: keep it alive until Wait.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := cmd.Start()
		started <- err
		if err == nil {
			err = cmd.Wait()
		}
		done <- err
	}()
	err := <-started
	if err != nil {
		t.Fatal("start isolated packet server", err)
	}
	stopped := false
	return func() {
		if !stopped {
			stopped = true
			_ = cmd.Process.Kill() // Go retains the process pidfd on Linux.
			<-done
		}
	}
}

func nativeDHCPContinuitySourceV4(t *testing.T, ctx context.Context, source *os.File) {
	t.Helper()
	for _, args := range [][]string{
		{"address", "add", "198.18.0.2/24", "dev", "source0"},
		{"route", "add", "default", "via", "198.18.0.1", "dev", "source0"},
	} {
		cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", append([]string{"--net=/proc/self/fd/3", "--", "/usr/bin/ip"}, args...)...)
		cmd.ExtraFiles = []*os.File{source}
		cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("configure pinned laboratory source: %v %s", err, output)
		}
	}
}

func nativeDHCPRenewalEvidenceV4(t *testing.T, cuts []nativeDHCPCutV4, checkpoint nativeDHCPContinuityCheckpointV4, traffic nativeDHCPContinuityReportV4) {
	t.Helper()
	lower, upper := make([]int64, len(cuts)), make([]int64, len(cuts))
	for i, cut := range cuts {
		lower[i], upper[i] = cut.LowerNS, cut.UpperNS
		var missing uint64
		for _, probe := range traffic.Missing {
			if probe.SentBootNS >= cut.CloseStart && probe.SentBootNS <= cut.Opened {
				missing++
			}
		}
		raw, err := json.Marshal(struct {
			Cycle                   int             `json:"cycle"`
			Cut                     nativeDHCPCutV4 `json:"cut"`
			MissingSentDuringBounds uint64          `json:"udp_missing_probes_sent_during_cut_bounds"`
		}{i + 1, cut, missing})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("ANDEIVA_NATIVE_RENEWAL_CUT_V4 %s", raw)
	}
	loMin, loMedian, loMax := nativeDurationSummaryV4(lower)
	hiMin, hiMedian, hiMax := nativeDurationSummaryV4(upper)
	t.Logf("ANDEIVA_NATIVE_RENEWAL_SUMMARY_V4 lower_ns_min_median_max=%d,%d,%d upper_ns_min_median_max=%d,%d,%d alpha_max_cut_ns=%d product_slo=undefined", loMin, loMedian, loMax, hiMin, hiMedian, hiMax, int64(dhcpclient.EarlyRenewalAlphaCutBudgetV4))
	raw, err := json.Marshal(struct {
		Renewals        int                              `json:"renewals"`
		ProbeIntervalNS int64                            `json:"nominal_probe_interval_ns"`
		FlowWindowNS    int64                            `json:"maximum_flow_window_ns"`
		Checkpoint      nativeDHCPContinuityCheckpointV4 `json:"post_renewals_checkpoint"`
		Traffic         nativeDHCPContinuityReportV4     `json:"traffic"`
	}{len(cuts), int64(100 * time.Millisecond), int64(650 * time.Second), checkpoint, traffic})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ANDEIVA_NATIVE_RENEWAL_TRAFFIC_V4 %s", raw)
	t.Log("UDP missing counts are observed application datagrams after bounded drain; send errors and TCP retransmissions are reported separately. Cut bounds include readback overhead; echo gaps are not cut durations.")
}

func nativeDHCPJobsRetiredKernelV4(t *testing.T, ctx context.Context, gateway *os.File) {
	t.Helper()
	for _, name := range []string{"lan0", "wan0"} {
		cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", "/usr/bin/ip", "-j", "-4", "address", "show", "dev", name)
		cmd.ExtraFiles = []*os.File{gateway}
		cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
		data, err := cmd.Output()
		var links []struct {
			Name      string            `json:"ifname"`
			Addresses []json.RawMessage `json:"addr_info"`
		}
		if err != nil || len(data) > 64<<10 || json.Unmarshal(data, &links) != nil || len(links) > 1 || len(links) == 1 && (links[0].Name != name || len(links[0].Addresses) != 0) {
			t.Fatal("retired interface retains IPv4 state", name, err)
		}
	}
	for _, inventory := range []struct {
		executable string
		args       []string
	}{
		{"/usr/bin/ip", []string{"-j", "-4", "route", "show", "table", "all"}},
		{"/usr/sbin/nft", []string{"-j", "list", "ruleset"}},
		{"/usr/bin/ss", []string{"-H", "-u", "-a", "-n"}},
	} {
		cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", append([]string{"--net=/proc/self/fd/3", "--", inventory.executable}, inventory.args...)...)
		cmd.ExtraFiles = []*os.File{gateway}
		cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
		data, err := cmd.Output()
		if err != nil || len(data) > 256<<10 {
			t.Fatal("retired inventory unavailable", inventory.executable, err)
		}
		if inventory.executable == "/usr/bin/ip" && strings.TrimSpace(string(data)) != "[]" || inventory.executable == "/usr/sbin/nft" && bytes.Contains(data, []byte("andeiva-dhcp-acquisition:v1")) || inventory.executable == "/usr/bin/ss" && len(bytes.TrimSpace(data)) != 0 {
			t.Fatal("retired scope retains routes, acquisition rules or UDP sockets")
		}
	}
}

type nativeDHCPJobsReportV4 struct {
	PID     int                         `json:"pid"`
	Phase   string                      `json:"phase"`
	Running string                      `json:"running"`
	Grant   configpoc.RoutedDHCPGrantV3 `json:"grant"`
}

func nativeDHCPJobsReportEmitV4(phase, running string, grant configpoc.RoutedDHCPGrantV3) error {
	raw, err := json.Marshal(nativeDHCPJobsReportV4{PID: os.Getpid(), Phase: phase, Running: running, Grant: grant})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stderr, "ANDEIVA_NATIVE_DHCP_JOBS %s\n", raw)
	return err
}

func nativeDHCPJobsWaitReportV4(t *testing.T, ctx context.Context, logs *nativeLogV3, phase string) nativeDHCPJobsReportV4 {
	t.Helper()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		for _, line := range strings.Split(logs.String(), "\n") {
			payload, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_DHCP_JOBS ")
			if !ok {
				continue
			}
			var report nativeDHCPJobsReportV4
			if json.Unmarshal([]byte(payload), &report) == nil && report.Phase == phase {
				return report
			}
		}
		if strings.Contains(logs.String(), "native role failed:") {
			t.Fatalf("waiting %s: %s", phase, logs.String())
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting %s: %v\n%s", phase, ctx.Err(), logs.String())
		case <-ticker.C:
		}
	}
}

// The failure report precedes deferred teardown. Capture only new, bounded
// fixed-schema diagnostics after the existing graceful close has finished.
func nativeDHCPJobsCloseTraceV4(logs *nativeLogV3, closeRuntime func() error) (string, error) {
	before := len(logs.String())
	err := closeRuntime()
	after := logs.String()
	if before > len(after) {
		return "", err
	}
	type record struct {
		Side      string `json:"side,omitempty"`
		Verb      string `json:"verb,omitempty"`
		Stage     string `json:"stage,omitempty"`
		BootNS    int64  `json:"boot_ns,omitempty"`
		ElapsedMS int64  `json:"elapsed_ms,omitempty"`
		Error     string `json:"error,omitempty"`
		Context   string `json:"context,omitempty"`
		Truncated bool   `json:"truncated,omitempty"`
		Dropped   uint64 `json:"dropped,omitempty"`
	}
	knownClass := func(v string) bool {
		switch v {
		case "ok", "deadline", "cancelled", "channel", "initial_waiting_v1", "no_lease_v1", "recovery", "conflict", "storage", "lease_unavailable", "observation", "uncertain", "scope", "other":
			return true
		}
		return false
	}
	var output strings.Builder
	var count, omitted int
	for _, line := range strings.Split(after[before:], "\n") {
		raw, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_DHCP_RPC ")
		if !ok || len(line)+1 > 512 {
			continue
		}
		var r record
		if firewallipc.Decode([]byte(raw), &r) != nil || r.BootNS < 0 || r.ElapsedMS < 0 {
			continue
		}
		if r.Truncated {
			if r.Side != "" || r.Verb != "" || r.Stage != "" || r.Error != "" || r.Context != "" || r.Dropped == 0 {
				continue
			}
		} else if !knownClass(r.Error) || !knownClass(r.Context) {
			continue
		} else if r.Side == "helper_stage" {
			if r.Verb != "" || !firewallipc.KnownRoutedDHCPFailureStageV1(r.Stage) {
				continue
			}
		} else if (r.Side != "helper" && r.Side != "client") || !firewallipc.RoutedDHCPVerbV3(r.Verb) || r.Stage != "" {
			continue
		}
		if count == 63 {
			omitted++
			continue
		}
		output.WriteString(line)
		output.WriteByte('\n')
		count++
	}
	if omitted != 0 {
		fmt.Fprintf(&output, "ANDEIVA_NATIVE_DHCP_RPC {\"truncated\":true,\"dropped\":%d}\n", omitted)
	}
	return output.String(), err
}

func nativeDHCPJobsKernelV4(t *testing.T, ctx context.Context, gateway *os.File, snapshot networkexecutor.LeaseSelectedSnapshotV3) {
	t.Helper()
	if _, err := networkexecutor.CanonicalLeaseSelectedSnapshotV3(snapshot); err != nil || snapshot.Address != "198.18.1.10/24" || snapshot.Gateway != "198.18.1.1" {
		t.Fatal("unverified/unexpected lease snapshot", err)
	}
	read := func(args ...string) []byte {
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(call, "/usr/bin/nsenter", append([]string{"--net=/proc/self/fd/3", "--", "/usr/bin/ip", "-j", "-4"}, args...)...)
		cmd.ExtraFiles = []*os.File{gateway}
		cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
		out, err := cmd.Output()
		if err != nil || len(out) > 64<<10 {
			t.Fatal("kernel readback", err)
		}
		return out
	}
	var links []struct {
		Name      string `json:"ifname"`
		Addresses []struct {
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(read("address", "show"), &links); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, link := range links {
		if link.Name != "lan0" && link.Name != "wan0" {
			continue
		}
		if len(link.Addresses) != 1 {
			t.Fatal("unexpected IPv4 inventory", link.Name)
		}
		seen[link.Name] = fmt.Sprintf("%s/%d", link.Addresses[0].Local, link.Addresses[0].Prefix)
	}
	if seen["lan0"] != "198.18.0.1/24" || seen["wan0"] != snapshot.Address {
		t.Fatal("selected WAN/LAN differs from actual kernel", seen)
	}
	var routes []struct {
		Destination string `json:"dst"`
		Gateway     string `json:"gateway"`
		Device      string `json:"dev"`
		Metric      uint32 `json:"metric"`
	}
	if err := json.Unmarshal(read("route", "show", "default"), &routes); err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Destination != "default" || routes[0].Gateway != snapshot.Gateway || routes[0].Device != "wan0" || routes[0].Metric != snapshot.Metric {
		t.Fatal("selected default route differs from kernel", routes)
	}
}

// Called only by nativeFactoriesV3 for the authenticated DHCPJobs launch profile.
// Uses the real Service and existing private controller; no local grant source.
func nativeDHCPJobsServeV4(ctx context.Context, r *RoutedOperationsRuntimeV3, ready func() error, binding adminauth.SessionBinding, launch RoutedLaunchContextV3) error {
	if !launch.DHCPJobsEnabled || !launch.Integrity || launch.Epoch < 1 || launch.Epoch > 2 || launch.DHCPRenewalV4 && launch.Epoch != 1 || r.DHCP == nil || !r.Service.RuntimeIntegrityReadyV1() {
		return errors.New("native DHCP profile/readiness differs")
	}
	flowReady := make(chan os.Signal, 1)
	if launch.DHCPRenewalV4 && launch.Epoch == 1 {
		signal.Notify(flowReady, syscall.SIGUSR2)
		defer signal.Stop(flowReady)
	}
	current, err := r.Service.Current(binding, "routed")
	if err != nil || current.Routed == nil {
		return errors.Join(err, ErrUnavailable)
	}
	observed, err := r.routed.Call(ctx, "observe", struct{}{})
	if err != nil || observed.Observed.Revision != current.Global.Running || observed.Observed.Receipt.Phase != "idle" {
		return errors.Join(err, ErrUnavailable)
	}
	if err = ready(); err != nil {
		return err
	}
	before := current.Routed.Startup.Hash // Seed Startup is NoNetwork and is never saved here.
	if launch.Epoch == 1 {
		if current.Snapshot.Running.Config.Routed != nil {
			return errors.New("native fixture did not start NoNetwork")
		}
		candidate, err := nativeDHCPJobsCandidateV4()
		if err != nil {
			return err
		}
		for _, request := range []configpoc.OperationRequestV2{{Kind: configpoc.OpStage, Config: &candidate.Config}, {Kind: configpoc.OpValidate}} {
			if _, err = nativeDHCPJobsOperationV4(ctx, r, binding, request, true); err != nil {
				return fmt.Errorf("native %s: %w", request.Kind, err)
			}
		}
		seconds := uint64(120)
		committed, err := nativeDHCPJobsOperationV4(ctx, r, binding, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds}, true)
		if err != nil || committed.Current.Confirmation == nil {
			return fmt.Errorf("native commit: %w", errors.Join(err, ErrUnavailable))
		}
		_, err = nativeDHCPJobsOperationV4(ctx, r, binding, configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: committed.Operation.ID, Target: committed.Current.RunningRevision}, false)
		if err != nil {
			return fmt.Errorf("native confirm: %w", err)
		}
		if err = nativeDHCPJobsInspectV4(ctx, r); err != nil {
			return fmt.Errorf("native post-confirm inspection: %w", err)
		}
	}
	first, err := nativeDHCPJobsLeaseV4(ctx, r, 0, 35*time.Second)
	if err != nil {
		return fmt.Errorf("native acquire/recover: %w", err)
	}
	current, err = r.Service.Current(binding, "routed")
	if err != nil || current.Snapshot.Running.Config.Routed == nil || current.Routed.Startup.Hash != before {
		return errors.Join(err, ErrUnavailable)
	}
	if launch.Epoch == 1 {
		if err = nativeDHCPJobsReportEmitV4("bound", current.Global.Running, first); err != nil {
			return err
		}
		if launch.DHCPRenewalV4 {
			select {
			case <-flowReady:
			case <-ctx.Done():
				return ctx.Err()
			}
			// Renewals before flow readiness cannot satisfy continuity acceptance.
			// Capture the authenticated owner's epoch after READY without a second
			// reconciliation/Live. The controller can lag an already delivered hook;
			// such a hook must not count toward ten subsequent renewals.
			r.DHCP.mu.Lock()
			renewed, err := r.DHCP.remote.Current(ctx)
			work := r.DHCP.work
			r.DHCP.mu.Unlock()
			if err != nil || work == "" || renewed.Epoch < first.Epoch || renewed.Snapshot.Fact().Owner != first.Snapshot.Fact().Owner {
				return errors.Join(err, errors.New("native ready owner lost its verified grant"))
			}
			if err = nativeDHCPJobsReportEmitV4("flow-ready", current.Global.Running, renewed); err != nil {
				return err
			}
			for i := 0; i < nativeDHCPEarlyRenewalSamplesV4; i++ {
				next, err := nativeDHCPJobsLeaseV4(ctx, r, renewed.Epoch, 65*time.Second)
				if err != nil {
					return fmt.Errorf("native early renewal %d: %w", i+1, err)
				}
				if next.Epoch != renewed.Epoch+1 || next.Snapshot.Fact().Owner != first.Snapshot.Fact().Owner || next.Snapshot.DeadlineBootNS <= renewed.Snapshot.DeadlineBootNS {
					return fmt.Errorf("native early renewal %d skipped an epoch, changed owner or retained deadline: %w", i+1, ErrUnavailable)
				}
				renewed = next
				if err = nativeDHCPJobsReportEmitV4(fmt.Sprintf("renewal-%d", i+1), current.Global.Running, renewed); err != nil {
					return err
				}
			}
			if err = nativeDHCPJobsReportEmitV4("renewed", current.Global.Running, renewed); err != nil {
				return err
			}
			// A second parent ACK follows Checkpoint and Stop on the same sockets.
			select {
			case <-flowReady:
			case <-ctx.Done():
				return ctx.Err()
			}
			if err = nativeDHCPJobsRetireV4(ctx, r, binding, before); err != nil {
				return err
			}
		} else {
			renewed, err := nativeDHCPJobsLeaseV4(ctx, r, first.Epoch, 90*time.Second)
			if err != nil {
				return fmt.Errorf("native natural renewal: %w", err)
			}
			if err = nativeDHCPJobsReportEmitV4("renewed", current.Global.Running, renewed); err != nil {
				return err
			}
		}

	} else {
		if err = nativeDHCPJobsReportEmitV4("restarted", current.Global.Running, first); err != nil {
			return err
		}
		seconds := uint64(120)
		_, rollbackErr := nativeDHCPJobsOperationV4(ctx, r, binding, configpoc.OperationRequestV2{Kind: configpoc.OpRollback, Target: before, ConfirmSeconds: &seconds}, false)
		if !errors.Is(rollbackErr, configpoc.ErrRecovery) && !errors.Is(rollbackErr, configpoc.ErrConflict) {
			return fmt.Errorf("native active DHCP rollback did not fence: %v", rollbackErr)
		}
		after, err := r.Service.Current(binding, "routed")
		if err != nil || after.Global.Running != current.Global.Running || after.Routed.Confirmation != nil {
			return errors.Join(err, ErrUnavailable)
		}
		// This outer fixture budget includes reconciliation and a separate Live
		// read; each authenticated RPC retains its own unchanged production bound.
		live, err := nativeDHCPJobsLeaseV4(ctx, r, 0, 10*time.Second)
		if err != nil || live.Snapshot.Fact().Owner != first.Snapshot.Fact().Owner {
			return errors.Join(err, ErrUnavailable)
		}
		if err = nativeDHCPJobsReportEmitV4("rollback-fenced", after.Global.Running, live); err != nil {
			return err
		}
		if err = nativeDHCPJobsRetireV4(ctx, r, binding, before); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return nil
}

func nativeDHCPJobsRetireV4(ctx context.Context, r *RoutedOperationsRuntimeV3, binding adminauth.SessionBinding, before string) error {
	// Retire through the authenticated writer before closing the supervisor.
	// No force-release, store rewrite or acquisition-instance replacement.
	r.DHCP.closeSchedulerV4()
	if err := r.DHCP.Withdraw(ctx); err != nil {
		return fmt.Errorf("native orderly withdrawal: %w", err)
	}
	seconds := uint64(120)
	rolled, err := nativeDHCPJobsOperationV4(ctx, r, binding, configpoc.OperationRequestV2{Kind: configpoc.OpRollback, Target: before, ConfirmSeconds: &seconds}, true)
	if err != nil || rolled.Current.Confirmation == nil {
		return fmt.Errorf("native orderly rollback: %w", errors.Join(err, ErrUnavailable))
	}
	_, err = nativeDHCPJobsOperationV4(ctx, r, binding, configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: rolled.Operation.ID, Target: rolled.Current.RunningRevision}, false)
	if err != nil {
		return fmt.Errorf("native orderly rollback confirm: %w", err)
	}
	if err = nativeDHCPJobsInspectV4(ctx, r); err != nil {
		return fmt.Errorf("native orderly retirement inspection: %w", err)
	}
	after, err := r.Service.Current(binding, "routed")
	if err != nil || after.Global.Running != before || after.Snapshot.Running.Config.Routed != nil || after.Routed.Confirmation != nil || r.routed.DHCPSelectedV4() {
		return errors.Join(err, ErrUnavailable)
	}
	if err = nativeDHCPJobsReportEmitV4("retired", after.Global.Running, configpoc.RoutedDHCPGrantV3{}); err != nil {
		return err
	}
	return nil
}

func nativeDHCPJobsCandidateV4() (configpoc.Revision, error) {
	policy := routednft.LabPolicy()
	plan := policy.Network.Config
	for i := range plan.Interfaces {
		if plan.Interfaces[i].Role == networkplan.WAN {
			plan.Interfaces[i].IPv4 = networkplan.IPv4{Mode: "dhcp"}
		}
	}
	var err error
	policy.Network, err = networkplan.Canonical(plan)
	if err != nil {
		return configpoc.Revision{}, err
	}
	for i := range policy.Rules {
		policy.Rules[i].Destination = "198.18.1.1/32"
	}
	return configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
}

// Runs without privileges: malformed fixture schema must fail before lab time.
func TestRoutedDHCPJobsV4NativeCandidate(t *testing.T) {
	candidate, err := nativeDHCPJobsCandidateV4()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := networkexecutor.CanonicalLANBootstrapPlanV3(candidate.Config.Routed.Network)
	if err != nil || plan.Hash != candidate.Config.Routed.Network.Hash || candidate.Config.LocalServices != nil {
		t.Fatal("canonical DHCP-only fixture", err)
	}
	var lan, wan int
	for _, iface := range plan.Config.Interfaces {
		if iface.Role == networkplan.LAN && iface.IPv4.Mode == "static" && iface.IPv4.Address == "198.18.0.1/24" {
			lan++
		}
		if iface.Role == networkplan.WAN && iface.IPv4.Mode == "dhcp" && iface.IPv4.Address == "" && iface.IPv4.Gateway == "" {
			wan++
		}
	}
	if lan != 1 || wan != 1 {
		t.Fatal("fixture invented WAN address or changed LAN")
	}
}

func nativeDHCPJobsInspectV4(ctx context.Context, r *RoutedOperationsRuntimeV3) error {
	r.DHCP.mu.Lock()
	defer r.DHCP.mu.Unlock()
	err := r.Service.InspectRuntimeV1(ctx)
	r.DHCP.afterInspectionV4(err, r.routed.DHCPSelectedV4())
	return err
}

func nativeDHCPJobsOperationV4(ctx context.Context, r *RoutedOperationsRuntimeV3, binding adminauth.SessionBinding, request configpoc.OperationRequestV2, inspect bool) (configpoc.ResultV2, error) {
	var result configpoc.ResultV2
	if inspect {
		if err := nativeDHCPJobsInspectV4(ctx, r); err != nil {
			return result, err
		}
	}
	status, err := r.Service.Status(binding)
	if err != nil {
		return result, err
	}
	ns, err := r.Service.Namespace(binding, "routed", time.Hour)
	if err != nil {
		return result, err
	}
	op, err := r.Service.Admit(binding, ns.ID, status.GlobalGeneration, request)
	if err != nil {
		return result, err
	}
	return r.Service.Execute(ctx, binding, op.ID)
}

func nativeDHCPJobsLeaseV4(parent context.Context, r *RoutedOperationsRuntimeV3, after uint64, budget time.Duration) (configpoc.RoutedDHCPGrantV3, error) {
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	trace := nativeDHCPJobsWaitTraceV4{start: time.Now(), output: os.Stderr}
	var last error
	var attempt uint64
	for {
		attempt++
		sample := nativeDHCPJobsWaitSampleV4{Stage: "reconcile", AfterEpoch: after, Attempt: attempt}
		started := time.Now()
		last = r.DHCP.Reconcile(ctx)
		sample.ReconcileMS = time.Since(started).Milliseconds()
		// Post-call progress only: another scheduler iteration may have run.
		// Never block reconciliation or read the selected store for diagnostics.
		if r.DHCP.mu.TryLock() {
			epoch, work := r.DHCP.grant.Epoch, r.DHCP.work != ""
			sample.ControllerEpoch, sample.ControllerWork = &epoch, &work
			r.DHCP.mu.Unlock()
		}
		sample.IntegrityReady = r.Service.RuntimeIntegrityReadyV1()
		sample.SelectedHint = r.routed.DHCPSelectedV4()
		if last == nil {
			r.DHCP.mu.Lock()
			started = time.Now()
			grant, e := r.DHCP.remote.Current(ctx)
			sample.CurrentMS = time.Since(started).Milliseconds()
			sample.Stage, sample.Epoch = "current", grant.Epoch
			work := r.DHCP.work
			workPresent := work != ""
			sample.Work = &workPresent
			if e == nil && work != "" && grant.Epoch > after && reflect.DeepEqual(grant, r.DHCP.grant) {
				started = time.Now()
				_, e = r.routed.Call(ctx, "dhcp_live", firewallipc.RoutedDHCPRequestV3{Work: work})
				sample.Stage, sample.LiveMS = "live", time.Since(started).Milliseconds()
				if e == nil {
					r.DHCP.mu.Unlock()
					if err := trace.emit(time.Now(), sample, nil, true); err != nil {
						return configpoc.RoutedDHCPGrantV3{}, err
					}
					return grant, nil
				}
			} else if e == nil {
				sample.Stage = "waiting_epoch_or_selected_work"
				e = ErrUnavailable
			}
			r.DHCP.mu.Unlock()
			last = e
		}
		if err := trace.emit(time.Now(), sample, errors.Join(last, ctx.Err()), ctx.Err() != nil); err != nil {
			return configpoc.RoutedDHCPGrantV3{}, err
		}
		select {
		case <-ctx.Done():
			if err := trace.emit(time.Now(), sample, errors.Join(ctx.Err(), last), true); err != nil {
				return configpoc.RoutedDHCPGrantV3{}, err
			}
			return configpoc.RoutedDHCPGrantV3{}, errors.Join(ctx.Err(), last)
		case <-ticker.C:
		}
	}
}

type nativeDHCPJobsWaitSampleV4 struct {
	Stage           string  `json:"stage"`
	Error           string  `json:"error"`
	Attempt         uint64  `json:"attempt"`
	ElapsedMS       int64   `json:"elapsed_ms"`
	ReconcileMS     int64   `json:"reconcile_ms"`
	CurrentMS       int64   `json:"current_ms"`
	LiveMS          int64   `json:"live_ms"`
	AfterEpoch      uint64  `json:"after_epoch"`
	Epoch           uint64  `json:"epoch"`
	Work            *bool   `json:"work,omitempty"`
	IntegrityReady  bool    `json:"integrity_ready"`
	SelectedHint    bool    `json:"selected_hint"`
	Final           bool    `json:"final"`
	ControllerEpoch *uint64 `json:"controller_epoch,omitempty"`
	ControllerWork  *bool   `json:"controller_work,omitempty"`
}

// Test-only, bounded measurements of existing calls. No additional RPC, packet,
// owner operation or selection read is issued to produce this diagnostic.
type nativeDHCPJobsWaitTraceV4 struct {
	start, last time.Time
	output      io.Writer
	reports     int
	final       bool
	lastClass   string
}

func (d *nativeDHCPJobsWaitTraceV4) emit(now time.Time, sample nativeDHCPJobsWaitSampleV4, err error, final bool) error {
	if d.final {
		return nil
	}
	sample.Error = "ok"
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		sample.Error = "deadline"
	case errors.Is(err, context.Canceled):
		sample.Error = "cancelled"
	case errors.Is(err, firewallipc.ErrChannel):
		sample.Error = "channel"
	case errors.Is(err, firewallipc.ErrRoutedDHCPWaitingV1):
		sample.Error = "initial_waiting_v1"
	case errors.Is(err, firewallipc.ErrRoutedDHCPNoLeaseV1):
		sample.Error = "no_lease_v1"
	case errors.Is(err, configpoc.ErrConflict), errors.Is(err, recoveryreserve.ErrConflict):
		sample.Error = "conflict"
	case errors.Is(err, configpoc.ErrStorage), errors.Is(err, recoveryreserve.ErrUnavailable):
		sample.Error = "storage"
	case errors.Is(err, recoveryreserve.ErrFull), err != nil && err.Error() == "ANDEIVA_OPERATION_LIMITED":
		sample.Error = "limited"
	case errors.Is(err, ErrIdentity):
		sample.Error = "identity"
	case errors.Is(err, configpoc.ErrRecovery):
		sample.Error = "recovery"
	case errors.Is(err, ErrUnavailable):
		sample.Error = "unavailable"
	case err != nil:
		sample.Error = "other"
	}
	// Capture the first new failure class even inside the periodic interval;
	// retain the same absolute 23 samples plus one final record bound.
	if !final && (d.reports >= 23 || sample.Error == d.lastClass && !d.last.IsZero() && now.Sub(d.last) < 5*time.Second) {
		return nil
	}
	sample.ElapsedMS, sample.Final = now.Sub(d.start).Milliseconds(), final
	data, e := json.Marshal(sample)
	if e != nil {
		return e
	}
	_, e = fmt.Fprintf(d.output, "ANDEIVA_NATIVE_DHCP_WAIT %s\n", data)
	d.last, d.final = now, final
	d.lastClass = sample.Error
	d.reports++
	return e
}

type nativeDHCPJobsSocketV4 struct {
	PID    int    `json:"pid"`
	Run    string `json:"run"`
	Socket string `json:"socket"`
}

func nativeDHCPJobsSocketIdentityV4(conn *net.UnixConn, peer routedDHCPJobPeerV4) (string, error) {
	if conn == nil || peer.pid <= 1 {
		return "", ErrIdentity
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return "", err
	}
	var identity string
	err = raw.Control(func(fd uintptr) {
		if fd > math.MaxInt32 {
			return
		}
		var stat unix.Stat_t
		kind, e := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		cred, ce := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e == nil && ce == nil && kind == unix.SOCK_SEQPACKET && unix.Fstat(int(fd), &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFSOCK && stat.Ino != 0 && int(cred.Pid) == peer.pid && cred.Uid == peer.uid && cred.Gid == peer.gid {
			identity = fmt.Sprintf("socket:[%d]", stat.Ino)
		}
	})
	if err != nil || identity == "" {
		return "", ErrIdentity
	}
	return identity, nil
}

// FD15 is validated at exec adoption, then net.FileConn duplicates it and the
// original closes. Report the adopted endpoint; its descriptor number can move.
func nativeDHCPJobsSocketReportV4(c RoutedLaunchContextV3) error {
	if !c.DHCPJobsEnabled || !c.Integrity || c.dhcpJobs == nil || c.dhcpJobs.peer.pid != os.Getppid() || c.dhcpJobs.peer.uid != 0 || c.dhcpJobs.peer.gid != 0 {
		return ErrIdentity
	}
	identity, err := nativeDHCPJobsSocketIdentityV4(c.dhcpJobs.conn, c.dhcpJobs.peer)
	if err != nil {
		return err
	}
	data, err := json.Marshal(nativeDHCPJobsSocketV4{os.Getpid(), c.Metadata.RunID, identity})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stderr, "ANDEIVA_NATIVE_DHCP_SOCKET %s\n", data)
	return err
}

func nativeDHCPJobsSocketPresentV4(pid int, identity string) (bool, error) {
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return false, err
	}
	for _, fd := range fds {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue // A concurrent close, including ReadDir's own descriptor.
		}
		if err != nil {
			return false, err
		}
		if link == identity {
			return true, nil
		}
	}
	return false, nil
}

func nativeDHCPJobsPrivilegesV4(t *testing.T, helper, api int, m Metadata, logs *nativeLogV3) {
	t.Helper()
	var reported nativeDHCPJobsSocketV4
	count := 0
	for _, line := range strings.Split(logs.String(), "\n") {
		if payload, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_DHCP_SOCKET "); ok {
			if err := json.Unmarshal([]byte(payload), &reported); err != nil {
				t.Fatal("invalid helper socket report", err)
			}
			count++
		}
	}
	if count != 1 || reported.PID != helper || reported.Run != m.RunID || !strings.HasPrefix(reported.Socket, "socket:[") {
		t.Fatal("helper socket report differs from supervised child")
	}
	if found, err := nativeDHCPJobsSocketPresentV4(helper, reported.Socket); err != nil || !found {
		t.Fatal("helper missing adopted private endpoint", err)
	}
	for _, process := range []struct {
		pid    int
		helper bool
	}{{helper, true}, {api, false}} {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", process.pid))
		if err != nil || privilegeFields(string(status), process.helper) != nil {
			t.Fatal("native child privileges", err)
		}
		ns, err := namespaceID(fmt.Sprintf("/proc/%d/ns/net", process.pid))
		want := m.HostNamespace
		if process.helper {
			want = m.GatewayNamespace
		}
		if err != nil || ns != want {
			t.Fatal("native child namespace", err)
		}
	}
	if found, err := nativeDHCPJobsSocketPresentV4(api, reported.Socket); err != nil || found {
		t.Fatal("API inherited private DHCP job endpoint or could not be inspected", err)
	}
}

func TestRoutedDHCPJobsV4NativeSocketAdoption(t *testing.T) {
	root, inherited, err := routedDHCPJobPairV4()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	defer inherited.Close()
	path := fmt.Sprintf("/proc/self/fd/%d", inherited.Fd())
	want, err := os.Readlink(path)
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := routedDHCPJobSocketV4(inherited)
	if err != nil {
		t.Fatal(err)
	}
	defer adopted.Close()
	regular, err := os.CreateTemp(t.TempDir(), "reused-descriptor")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	// Replace our still-owned original descriptor atomically, without a race
	// against unrelated opens. The production FileConn duplicate remains live.
	if err = unix.Dup3(int(regular.Fd()), int(inherited.Fd()), unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	if observed, err := os.Readlink(path); err != nil || strings.HasPrefix(observed, "socket:[") {
		t.Fatal("fixture did not reuse original descriptor for a regular file", err)
	}
	peer := routedDHCPJobPeerV4{pid: os.Getpid(), uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
	got, err := nativeDHCPJobsSocketIdentityV4(adopted, peer)
	if err != nil || got != want {
		t.Fatal("adopted endpoint changed", err)
	}
	if found, err := nativeDHCPJobsSocketPresentV4(os.Getpid(), got); err != nil || !found {
		t.Fatal("adopted endpoint not found after descriptor reuse", err)
	}
	other, err := nativeDHCPJobsSocketIdentityV4(root, peer)
	if err != nil || other == got {
		t.Fatal("different socket confused with helper endpoint", err)
	}
	for _, wrong := range []routedDHCPJobPeerV4{{pid: peer.pid + 1, uid: peer.uid, gid: peer.gid}, {pid: peer.pid, uid: peer.uid ^ 1, gid: peer.gid}, {pid: peer.pid, uid: peer.uid, gid: peer.gid ^ 1}} {
		if identity, err := nativeDHCPJobsSocketIdentityV4(adopted, wrong); err == nil || identity != "" {
			t.Fatal("socket accepted with wrong peer credentials")
		}
	}
	if err = adopted.Close(); err != nil {
		t.Fatal(err)
	}
	if found, err := nativeDHCPJobsSocketPresentV4(os.Getpid(), got); err != nil || found {
		t.Fatal("closed endpoint confused with another live socket", err)
	}
}

func TestRoutedDHCPJobsV4NativeWaitTraceBounded(t *testing.T) {
	var output bytes.Buffer
	start := time.Unix(100, 0)
	d := nativeDHCPJobsWaitTraceV4{start: start, output: &output}
	sample := nativeDHCPJobsWaitSampleV4{Stage: "reconcile", ReconcileMS: 2300, Attempt: 1}
	if err := d.emit(start, sample, ErrUnavailable, false); err != nil {
		t.Fatal(err)
	}
	if err := d.emit(start.Add(time.Second), sample, ErrUnavailable, false); err != nil || d.reports != 1 {
		t.Fatal("trace ignored rate bound", err)
	}
	for i := 1; i <= 100; i++ {
		sample.Attempt = uint64(i + 1)
		if err := d.emit(start.Add(time.Duration(i)*5*time.Second), sample, errors.New("must not appear in output"), false); err != nil {
			t.Fatal(err)
		}
	}
	if d.reports != 23 || strings.Contains(output.String(), "must not appear") {
		t.Fatal("unbounded or unsanitized trace")
	}
	if err := d.emit(start.Add(501*time.Second), sample, context.DeadlineExceeded, true); err != nil || d.reports != 24 {
		t.Fatal("missing final trace after report cap", err)
	}
	if err := d.emit(start.Add(502*time.Second), sample, nil, true); err != nil || d.reports != 24 {
		t.Fatal("duplicate final trace", err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	var final nativeDHCPJobsWaitSampleV4
	raw, ok := strings.CutPrefix(lines[len(lines)-1], "ANDEIVA_NATIVE_DHCP_WAIT ")
	if !ok || json.Unmarshal([]byte(raw), &final) != nil || !final.Final || final.Error != "deadline" || final.ElapsedMS != 501000 || final.ReconcileMS != 2300 || final.Attempt != 101 || final.Work != nil {
		t.Fatal("incorrect final measurement", final)
	}
}

func TestRoutedDHCPJobsV4NativeWaitTraceFailureClasses(t *testing.T) {
	cases := []struct {
		err  error
		code string
	}{
		{firewallipc.ErrRoutedDHCPWaitingV1, "initial_waiting_v1"},
		{firewallipc.ErrRoutedDHCPNoLeaseV1, "no_lease_v1"},
		{firewallipc.ErrChannel, "channel"},
		{configpoc.ErrConflict, "conflict"},
		{configpoc.ErrStorage, "storage"},
		{errors.New("ANDEIVA_OPERATION_LIMITED"), "limited"},
		{recoveryreserve.ErrFull, "limited"},
		{configpoc.ErrRecovery, "recovery"},
		{errors.New("private underlying detail"), "other"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			var output bytes.Buffer
			start := time.Unix(100, 0)
			d := nativeDHCPJobsWaitTraceV4{start: start, output: &output}
			if err := d.emit(start, nativeDHCPJobsWaitSampleV4{}, nil, false); err != nil {
				t.Fatal(err)
			}
			epoch := uint64(7)
			work := true
			sample := nativeDHCPJobsWaitSampleV4{Stage: "reconcile", ControllerEpoch: &epoch, ControllerWork: &work}
			if err := d.emit(start.Add(time.Millisecond), sample, errors.Join(tc.err), false); err != nil {
				t.Fatal(err)
			}
			if d.reports != 2 {
				t.Fatal("first new failure suppressed by interval")
			}
			lines := strings.Split(strings.TrimSpace(output.String()), "\n")
			raw, ok := strings.CutPrefix(lines[1], "ANDEIVA_NATIVE_DHCP_WAIT ")
			var got nativeDHCPJobsWaitSampleV4
			if !ok || json.Unmarshal([]byte(raw), &got) != nil || got.Error != tc.code || got.ControllerEpoch == nil || *got.ControllerEpoch != 7 || got.ControllerWork == nil || !*got.ControllerWork || strings.Contains(output.String(), "private underlying") {
				t.Fatal("invalid failure classification", got)
			}
		})
	}
	// Class churn cannot exceed the existing absolute record cap.
	var output bytes.Buffer
	start := time.Unix(100, 0)
	d := nativeDHCPJobsWaitTraceV4{start: start, output: &output}
	for i := 0; i < 100; i++ {
		err := firewallipc.ErrChannel
		if i%2 == 0 {
			err = firewallipc.ErrRoutedDHCPWaitingV1
		}
		if e := d.emit(start.Add(time.Duration(i)*time.Millisecond), nativeDHCPJobsWaitSampleV4{}, err, false); e != nil {
			t.Fatal(e)
		}
	}
	if d.reports != 23 {
		t.Fatal("failure churn bypassed report bound", d.reports)
	}
}

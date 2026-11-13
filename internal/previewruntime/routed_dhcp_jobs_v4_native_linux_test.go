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
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routednft"
	"golang.org/x/sys/unix"
)

// Explicit root laboratory only. The packet server is a test peer; acquisition,
// private FD15/SCM transport, selected store, helper and kernel executors are real.
func TestNativeRoutedDHCPJobsV4(t *testing.T) {
	if os.Getenv("ANDEIVA_NATIVE_DHCP_JOBS_V4") != "1" {
		t.Skip("requires authorized isolated root laboratory harness")
	}
	if os.Getenv("CI") != "" || os.Getuid() != 0 || os.Geteuid() != 0 || routedDHCPOwnerCgroupV3() != nil {
		t.Fatal("root laboratory only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
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
	supervisor, e := StartRoutedLaunchV3(ctx, RoutedLaunchResourcesV3{DHCPJobs: true, Metadata: metadata, Identities: nativeIdentitiesV3, Gateway: namespaces[0], Host: host, Directory: directory, IntegrityRoot: private, Store: resource(0), Admission: resource(1), Plan: resource(2), Emergency: resource(3), Budget: nativeSelectionBudgetV3()}, &logs)
	if e != nil {
		t.Fatalf("native DHCP launch failed: %v\n%s", e, logs.String())
	}
	defer supervisor.Close()
	helper, api := supervisor.PIDs()
	nativeDHCPJobsPrivilegesV4(t, helper, api, metadata)
	bound := nativeDHCPJobsWaitReportV4(t, ctx, &logs, "bound")
	nativeDHCPJobsKernelV4(t, ctx, namespaces[0], bound.Grant.Snapshot)
	renewed := nativeDHCPJobsWaitReportV4(t, ctx, &logs, "renewed")
	if renewed.Grant.Epoch <= bound.Grant.Epoch || renewed.Grant.Snapshot.DeadlineBootNS <= bound.Grant.Snapshot.DeadlineBootNS || renewed.Grant.Snapshot.Fact().Owner != bound.Grant.Snapshot.Fact().Owner || renewed.Running != bound.Running {
		t.Fatal("renewal reused an epoch/deadline or replaced owner/policy")
	}
	nativeDHCPJobsKernelV4(t, ctx, namespaces[0], renewed.Grant.Snapshot)
	if e = supervisor.RestartAPI(ctx); e != nil {
		t.Fatalf("API restart failed: %v\n%s", e, logs.String())
	}
	h2, a2 := supervisor.PIDs()
	if helper != h2 || api == a2 {
		t.Fatal("API restart replaced helper or reused API PID")
	}
	nativeDHCPJobsPrivilegesV4(t, h2, a2, metadata)
	restarted := nativeDHCPJobsWaitReportV4(t, ctx, &logs, "restarted")
	if restarted.Running != bound.Running || restarted.Grant.Snapshot.Fact().Owner != bound.Grant.Snapshot.Fact().Owner || restarted.Grant.Epoch < renewed.Grant.Epoch {
		t.Fatal("API restart lost selected policy or real producer incarnation")
	}
	nativeDHCPJobsWaitReportV4(t, ctx, &logs, "rollback-fenced")
	nativeDHCPJobsKernelV4(t, ctx, namespaces[0], restarted.Grant.Snapshot)
	if e = supervisor.Close(); e != nil {
		t.Fatal("grouped close", e)
	}
	stopServer()
	if strings.Contains(logs.String(), "native role failed:") {
		t.Fatalf("child failure: %s", logs.String())
	}
	t.Log("real selected DHCP acquisition, natural renewal, retained-helper API restart and active-work rollback refusal; lifecycle gate retirement, expiry/death and packet forwarding remain separate gates")
}

// udhcpd is only a test packet peer. The child joins the inherited WAN pin;
// no name/PID from the environment chooses a namespace or signal target.
func nativeDHCPJobsServerV4(t *testing.T, ctx context.Context, base string, wan *os.File, logs io.Writer) func() {
	t.Helper()
	if trustedRoutedExecutableV3("/usr/bin/busybox") != nil {
		t.Fatal("trusted busybox udhcpd test dependency missing")
	}
	conf := fmt.Sprintf("start 198.18.1.10\nend 198.18.1.10\ninterface sink0\nmax_leases 1\nmin_lease 60\nlease_file %s\npidfile %s\nopt subnet 255.255.255.0\nopt router 198.18.1.1\nopt lease 120\n", filepath.Join(base, "test-server.leases"), filepath.Join(base, "test-server.pid"))
	path := filepath.Join(base, "test-server.conf")
	if err := os.WriteFile(path, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", "/usr/bin/busybox", "udhcpd", "-f", path)
	cmd.ExtraFiles = []*os.File{wan}
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = logs, logs
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	runtime.LockOSThread()
	err := cmd.Start()
	runtime.UnlockOSThread()
	if err != nil {
		t.Fatal("start isolated packet server", err)
	}
	stopped := false
	return func() {
		if !stopped {
			stopped = true
			_ = cmd.Process.Kill() // Go retains the process pidfd on Linux.
			_ = cmd.Wait()
		}
	}
}

type nativeDHCPJobsReportV4 struct {
	Phase   string                      `json:"phase"`
	Running string                      `json:"running"`
	Grant   configpoc.RoutedDHCPGrantV3 `json:"grant"`
}

func nativeDHCPJobsReportEmitV4(phase, running string, grant configpoc.RoutedDHCPGrantV3) error {
	raw, err := json.Marshal(nativeDHCPJobsReportV4{phase, running, grant})
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
	if !launch.DHCPJobsEnabled || !launch.Integrity || launch.Epoch < 1 || launch.Epoch > 2 || r.DHCP == nil || !r.Service.RuntimeIntegrityReadyV1() {
		return errors.New("native DHCP profile/readiness differs")
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
		renewed, err := nativeDHCPJobsLeaseV4(ctx, r, first.Epoch, 90*time.Second)
		if err != nil {
			return fmt.Errorf("native natural renewal: %w", err)
		}
		if err = nativeDHCPJobsReportEmitV4("renewed", current.Global.Running, renewed); err != nil {
			return err
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
		live, err := nativeDHCPJobsLeaseV4(ctx, r, 0, 3*time.Second)
		if err != nil || live.Snapshot.Fact().Owner != first.Snapshot.Fact().Owner {
			return errors.Join(err, ErrUnavailable)
		}
		if err = nativeDHCPJobsReportEmitV4("rollback-fenced", after.Global.Running, live); err != nil {
			return err
		}
	}
	<-ctx.Done()
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
	r.DHCP.scheduleV4(err == nil && r.routed.DHCPSelectedV4())
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
	var last error
	for {
		last = r.DHCP.Reconcile(ctx)
		if last == nil {
			r.DHCP.mu.Lock()
			grant, e := r.DHCP.remote.Current(ctx)
			work := r.DHCP.work
			if e == nil && work != "" && grant.Epoch > after && reflect.DeepEqual(grant, r.DHCP.grant) {
				_, e = r.routed.Call(ctx, "dhcp_live", firewallipc.RoutedDHCPRequestV3{Work: work})
				if e == nil {
					r.DHCP.mu.Unlock()
					return grant, nil
				}
			}
			r.DHCP.mu.Unlock()
			last = e
		}
		select {
		case <-ctx.Done():
			return configpoc.RoutedDHCPGrantV3{}, errors.Join(ctx.Err(), last)
		case <-ticker.C:
		}
	}
}

func nativeDHCPJobsPrivilegesV4(t *testing.T, helper, api int, m Metadata) {
	t.Helper()
	jobSocket, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/15", helper))
	if err != nil || !strings.HasPrefix(jobSocket, "socket:[") {
		t.Fatal("helper missing private FD15", err)
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
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", api))
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", api, fd.Name()))
		if err == nil && link == jobSocket {
			t.Fatal("API inherited private DHCP job endpoint")
		}
	}
}

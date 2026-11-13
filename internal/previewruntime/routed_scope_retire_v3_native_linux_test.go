//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"golang.org/x/sys/unix"
)

const nativeScopeRetireCaptureV3 = "/fixture/first.json"

func nativeScopeRetireRootPathV3(path string) bool {
	const prefix = "/var/backups/andeiva-scope-retire."
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, "/root") || filepath.Clean(path) != path {
		return false
	}
	nonce := strings.TrimSuffix(strings.TrimPrefix(path, prefix), "/root")
	if len(nonce) != 8 {
		return false
	}
	for _, c := range nonce {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func nativeScopeRetireRootPropertiesV3(raw []byte, self int, invocation string) error {
	if self <= 1 || !validHex(invocation, 16) || len(raw) == 0 || len(raw) > 4096 {
		return ErrIdentity
	}
	wanted := map[string]string{"MainPID": strconv.Itoa(self), "InvocationID": invocation, "PrivateMounts": "yes"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return ErrIdentity
		}
		seen[key] = true
		if key == "RootDirectory" {
			if !nativeScopeRetireRootPathV3(value) {
				return ErrIdentity
			}
		} else if expected, ok := wanted[key]; !ok || value != expected {
			return ErrIdentity
		}
	}
	if len(seen) != 4 {
		return ErrIdentity
	}
	return nil
}

func nativeScopeRetireRootUnitV3(ctx context.Context) error {
	if trustedRoutedExecutableV3("/usr/bin/systemctl") != nil {
		return ErrIdentity
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, "/usr/bin/systemctl", "--no-pager", "show", "--property=RootDirectory", "--property=PrivateMounts", "--property=MainPID", "--property=InvocationID", "andeiva-preview-grouped.service")
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_OFFLINE=0"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 200 * time.Millisecond
	var out scopeRecoveryOutputV3
	cmd.Stdout = &out
	runtime.LockOSThread()
	err := cmd.Run()
	runtime.UnlockOSThread()
	if err != nil || call.Err() != nil {
		return ErrIdentity
	}
	return nativeScopeRetireRootPropertiesV3(out.Bytes(), os.Getpid(), os.Getenv("INVOCATION_ID"))
}

type nativeScopeRetireCapture struct {
	Version     int                `json:"version"`
	Launch      Metadata           `json:"launch"`
	Operational Metadata           `json:"operational"`
	Resources   nativeSeedResultV3 `json:"resources"`
	Invocation  string             `json:"invocation"`
}

func nativeScopeRetireIdentityV3(m Metadata) networkexecutor.OwnedNamespaceIdentity {
	return networkexecutor.OwnedNamespaceIdentity{UID: nativeIdentitiesV3.HelperUID, GID: nativeIdentitiesV3.IPCGID, Namespace: m.GatewayNamespace, Host: m.HostNamespace, BootID: m.BootID, RunID: m.RunID}
}

func nativeScopeRetireWriteV3(t *testing.T, path string, raw []byte, mode os.FileMode, uid, gid int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, mode)
	if err != nil {
		t.Fatal("create exact fixture file", path, err)
	}
	if err = f.Chmod(mode); err == nil {
		err = f.Chown(uid, gid)
	}
	if err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal("persist fixture file", path, err, closeErr)
	}
}

func nativeScopeRetireDirectoryV3(t *testing.T, path string, mode os.FileMode, uid, gid int) *os.Root {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal("create fixture directory", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	area, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = area.Close() })
	return area
}

// Fixed operations inside an authenticated fixture namespace only. Parent
// veth pairs never touch the host. MACVLAN is required by the real cleanup
// allowlist; the fixture does not broaden it to accept ordinary veth children.
func nativeScopeRetireLinksV3(t *testing.T, ctx context.Context, source, gateway *os.File, lan bool) {
	t.Helper()
	name, mac := "wan0", "02:00:00:00:02:01"
	if lan {
		name, mac = "lan0", "02:00:00:00:01:01"
	}
	operations := [][]string{
		{"link", "add", "parent0", "type", "veth", "peer", "name", "peer0"},
		{"link", "set", "parent0", "up"}, {"link", "set", "peer0", "up"},
		{"link", "add", "link", "parent0", "name", name, "address", mac, "netns", "/proc/self/fd/4", "type", "macvlan", "mode", "private"},
	}
	for _, args := range operations {
		nativeScopeRetireIPV3(t, ctx, source, gateway, args)
	}
	nativeScopeRetireIPV3(t, ctx, gateway, source, []string{"link", "set", name, "up"})
}

func nativeScopeRetireIPV3(t *testing.T, ctx context.Context, scope, other *os.File, args []string) {
	t.Helper()
	current, err := namespaceID("/proc/self/ns/net")
	info, statErr := scope.Stat()
	if err != nil || statErr != nil || info.Sys().(*syscall.Stat_t).Ino == current || !scopeRecoveryNamespaceV3(scope, unix.CLONE_NEWNET) || trustedRoutedExecutableV3("/usr/bin/nsenter") != nil || trustedRoutedExecutableV3("/usr/bin/ip") != nil {
		t.Fatal("isolated fixture namespace required")
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, "/usr/bin/nsenter", append([]string{"--net=/proc/self/fd/3", "--", "/usr/bin/ip"}, args...)...)
	cmd.ExtraFiles = []*os.File{scope, other}
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 200 * time.Millisecond
	var out scopeRecoveryOutputV3
	cmd.Stdout, cmd.Stderr = &out, &out
	runtime.LockOSThread()
	err = cmd.Run()
	runtime.UnlockOSThread()
	if err != nil || call.Err() != nil {
		t.Fatal("fixed isolated L2 operation", err, call.Err(), out.String())
	}
}

func nativeScopeRetireResourcesV3(t *testing.T, c nativeScopeRetireCapture) RoutedLaunchResourcesV3 {
	t.Helper()
	r := RoutedLaunchResourcesV3{Metadata: c.Operational, Identities: nativeIdentitiesV3, Budget: nativeSelectionBudgetV3(), StoreBudget: nativeBudgetV3()}
	out := []*RoutedReaderRootV3{&r.Store, &r.Admission, &r.Plan, &r.Emergency}
	for i, name := range []string{"store", "admission", "plan", "emergency"} {
		root, err := os.OpenRoot(filepath.Join(routedDeploymentDataV3, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = root.Close() })
		*out[i] = RoutedReaderRootV3{Root: root, Access: c.Resources.Access[i]}
		if i != 0 {
			out[i].Profile = c.Resources.Profiles[i-1]
		}
		if err = out[i].Access.CheckDirectory(root); err != nil {
			t.Fatal("captured root identity changed", err)
		}
	}
	return r
}

func nativeScopeRetireFirstV3(t *testing.T, ctx context.Context, area, operational *os.Root) {
	t.Helper()
	data, err := os.OpenRoot(routedDeploymentDataV3)
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	for _, name := range []string{"store", "admission", "plan", "emergency"} {
		nativeScopeRetireDirectoryV3(t, filepath.Join(routedDeploymentDataV3, name), 0700, 62001, 62004)
	}
	ipc := nativeScopeRetireDirectoryV3(t, routedDeploymentRunV3+"/ipc", 0750, 62002, 62003)
	nativeScopeRetireDirectoryV3(t, routedDeploymentRunV3+"/api", 0700, 62001, 62001)
	netns := nativeScopeRetireDirectoryV3(t, routedDeploymentRunV3+"/netns", 0700, 0, 0)
	sourceArea := nativeScopeRetireDirectoryV3(t, "/fixture/source", 0700, 0, 0)
	sinkArea := nativeScopeRetireDirectoryV3(t, "/fixture/sink", 0700, 0, 0)
	// Pins for the two fixture-only parent scopes live exclusively in the old
	// private mount namespace; that namespace is one of the seven stored FDs.
	gateway, err := CreateRoutedGatewayNamespaceV3(ctx, netns)
	if err != nil {
		t.Fatal(err)
	}
	source, err := CreateRoutedGatewayNamespaceV3(ctx, sourceArea)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := CreateRoutedGatewayNamespaceV3(ctx, sinkArea)
	if err != nil {
		t.Fatal(err)
	}
	// No deferred Close: failure retains pins/evidence, and success kills Root.
	host, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	hostID, err := namespaceID("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	bootRaw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	boot, err := canonicalBoot(bootRaw)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	launch := Metadata{SchemaVersion: 1, RunID: hex.EncodeToString(nonce[:]), BootID: boot, HostNamespace: hostID, GatewayNamespace: gateway.ID(), SourceNamespace: source.ID(), SinkNamespace: sink.ID()}
	managed := launch
	managed.SchemaVersion, managed.SourceNamespace, managed.SinkNamespace = RoutedMetadataSchemaVersion, 0, 0
	if launch.Validate() != nil || managed.ValidateRouted() != nil || nativeScopeRetireIdentityV3(launch) != nativeScopeRetireIdentityV3(managed) {
		t.Fatal("fixture topology changed selected owner identity")
	}
	nativeScopeRetireWriteV3(t, routedDeploymentRunV3+"/runtime.json", marshal(managed), 0644, 0, 0)
	slot, err := openRoutedRetirementSlotV3(operational)
	if err != nil {
		t.Fatal(err)
	}
	defer slot.Close()
	record, err := openScopeRecordSlotV3(operational, true)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Close()
	mount, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer mount.Close()
	underlay, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", gateway.underlay.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer underlay.Close()
	cgroup, err := os.Open("/sys/fs/cgroup" + routedSupervisorCgroupV3)
	if err != nil {
		t.Fatal(err)
	}
	defer cgroup.Close()
	efd, err := unix.Openat(int(cgroup.Fd()), "cgroup.events", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	events := os.NewFile(uintptr(efd), "native-retirement-events")
	defer events.Close()
	anchors := RoutedScopeRecoveryAnchorsV3{record.reader, gateway.File(), mount, underlay, gateway.directory, cgroup, events}
	raw, err := PrepareRoutedScopeRecoveryRecordV3(ctx, managed, nativeIdentitiesV3, anchors)
	if err != nil {
		t.Fatal("real anchor capture", err)
	}
	if err = record.publish(raw); err != nil {
		t.Fatal(err)
	}
	recovery, err := OpenRoutedScopeRecoveryV3(ctx, anchors)
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	if err = recovery.Store(ctx); err != nil {
		t.Fatal("actual FD store", err)
	}
	if err = recovery.VerifyStored(ctx); err != nil {
		t.Fatal(err)
	}
	nativeScopeRetireLinksV3(t, ctx, source.File(), gateway.File(), true)
	nativeScopeRetireLinksV3(t, ctx, sink.File(), gateway.File(), false)
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	credential := hex.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(credential))
	subject, err := configpoc.NewSubjectIDV2()
	if err != nil {
		t.Fatal(err)
	}
	auth := nativeAuthV3{Account: adminauth.Account{Username: "native-operator", Role: "admin", SubjectID: subject, CredentialRevision: hex.EncodeToString(digest[:]), CredentialSHA256: hex.EncodeToString(digest[:])}, Credential: credential}
	for name, raw := range map[string][]byte{"api-auth.json": marshal(auth), "api-audit.jsonl": nil, "seed-profiles.json": nil} {
		nativeScopeRetireWriteV3(t, filepath.Join(routedDeploymentDataV3, name), raw, 0600, 62001, 62001)
	}
	base, err := data.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	seed := exec.CommandContext(ctx, "/usr/bin/setpriv", "--reuid=62001", "--regid=62001", "--groups=62004", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", "/fixture/native.test", nativeSeedRoleV3)
	seed.ExtraFiles = []*os.File{base}
	seed.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	seed.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	var logs nativeLogV3
	seed.Stdout, seed.Stderr = &logs, &logs
	runtime.LockOSThread()
	err = seed.Run()
	runtime.UnlockOSThread()
	_ = base.Close()
	if err != nil {
		t.Fatal("real offline seed", err, logs.String())
	}
	raw, err = data.ReadFile("seed-profiles.json")
	var capture nativeScopeRetireCapture
	if err != nil || len(raw) > 8192 || firewallipc.Decode(raw, &capture.Resources) != nil {
		t.Fatal("seed resource profiles", err)
	}
	capture.Version, capture.Launch, capture.Operational, capture.Invocation = 1, launch, managed, os.Getenv("INVOCATION_ID")
	resources := nativeScopeRetireResourcesV3(t, capture)
	resources.Metadata, resources.Gateway, resources.Host, resources.Directory = launch, gateway.File(), host, ipc
	supervisor, err := StartRoutedLaunchV3(ctx, resources, &logs)
	if err != nil {
		t.Fatal("real NoNetwork boot", err, logs.String())
	}
	if err = supervisor.Close(); err != nil {
		t.Fatal("real child wait", err, logs.String())
	}
	if strings.Contains(logs.String(), "native role failed:") || !strings.Contains(logs.String(), `"FactoryOpened":true`) {
		t.Fatal("missing real boot boundary/readback", logs.String())
	}
	if err = waitRoutedCgroupDrainedV3(); err != nil {
		t.Fatal("children retained after wait", err)
	}
	nativeScopeRetireWriteV3(t, nativeScopeRetireCaptureV3, marshal(capture), 0600, 0, 0)
	if err = waitRoutedCgroupDrainedV3(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, "ANDEIVA_SCOPE_RETIRE_FIRST_STORED", capture.Invocation)
	if err = unix.Kill(os.Getpid(), unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	t.Fatal("SIGKILL unexpectedly returned")
}

func nativeScopeRetireSecondV3(t *testing.T, ctx context.Context, area, operational *os.Root, recovery *RoutedScopeRecoveryV3) {
	t.Helper()
	nativeScopeRetireWriteV3(t, "/fixture/recovery-attempt", []byte(os.Getenv("INVOCATION_ID")+"\n"), 0600, 0, 0)
	raw, err := readOwned(nativeScopeRetireCaptureV3, 0, 0, 0600, 16384)
	var capture nativeScopeRetireCapture
	if err != nil || firewallipc.Decode(raw, &capture) != nil || capture.Version != 1 || capture.Launch.Validate() != nil || capture.Operational.ValidateRouted() != nil || capture.Operational != recovery.record.Metadata || capture.Invocation != recovery.record.CgroupInvocation || capture.Invocation == os.Getenv("INVOCATION_ID") || nativeScopeRetireIdentityV3(capture.Launch) != nativeScopeRetireIdentityV3(capture.Operational) {
		t.Fatal("uncorrelated second invocation", err)
	}
	resources := nativeScopeRetireResourcesV3(t, capture)
	record, err := openScopeRecordSlotV3(operational, false)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Close()
	slot, err := openRoutedRetirementSlotV3(operational)
	if err != nil {
		t.Fatal(err)
	}
	defer slot.Close()
	before, err := record.read()
	if err != nil {
		t.Fatal(err)
	}
	assertPreserved := func() {
		t.Helper()
		after, e := record.read()
		if e != nil || !bytes.Equal(before, after) {
			t.Fatal("failed retirement changed manifest", e)
		}
		proof := make([]byte, RootRetirementReceiptSizeV3)
		if _, e = slot.file.ReadAt(proof, 0); e != nil || !bytes.Equal(proof, make([]byte, len(proof))) {
			t.Fatal("failed retirement issued receipt", e)
		}
		if e = recovery.VerifyStored(ctx); e != nil {
			t.Fatal("failed retirement removed stored anchors", e)
		}
	}
	assertPreserved()
	// A genuine held publication lock must refuse before network/teardown. This
	// is the existing checkpoint file, never a fabricated or replacement lock.
	barrier, err := openScopeRecoveryBarrierV3(ctx, resources.Store, nativeIdentitiesV3)
	if err != nil {
		t.Fatal("native publication barrier", err)
	}
	err = retireInheritedRoutedScopeResourcesV3(ctx, area, slot, record, recovery, nativeIdentitiesV3, resources)
	if closeErr := barrier.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err == nil {
		t.Fatal("retirement bypassed held writer lock")
	}
	assertPreserved()
	// Capture both actual cgroup identities and the original events FD. An
	// ENODEV observation is evidence of a blocked branch, never native PASS.
	group, err := os.Open("/sys/fs/cgroup" + routedSupervisorCgroupV3)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := scopeRecoveryIdentityV3(group)
	closeErr := group.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	events := make([]byte, 129)
	n, readErr := recovery.files[6].ReadAt(events, 0)
	deactivated, populated, err := scopeRecoveryOldEventsObservationV3(events[:n], readErr, recovery.record.Cgroup, current, capture.Invocation, os.Getenv("INVOCATION_ID"))
	if err != nil {
		t.Fatal("original cgroup observation", err)
	}
	fmt.Fprintf(os.Stdout, "ANDEIVA_SCOPE_RETIRE_CGROUP old=%d current=%d deactivated=%t populated=%t\n", recovery.record.Cgroup.Inode, current.Inode, deactivated, populated)
	err = retireInheritedRoutedScopeResourcesV3(ctx, area, slot, record, recovery, nativeIdentitiesV3, resources)
	if err != nil {
		if deactivated {
			assertPreserved()
			t.Fatal("ENODEV branch remains blocked; no retirement qualified", err)
		}
		t.Fatal("real retained-scope retirement failed; evidence retained", err)
	}
	if deactivated {
		t.Fatal("unreviewed ENODEV branch unexpectedly retired")
	}
	if !recovery.closed {
		t.Fatal("local retained anchors remain open")
	}
	proof := make([]byte, RootRetirementReceiptSizeV3)
	if _, err = slot.file.ReadAt(proof, 0); err != nil {
		t.Fatal(err)
	}
	receipt, err := DecodeRootRetirementReceiptV3(proof)
	if err != nil || receipt.Old != nativeScopeRetireIdentityV3(capture.Operational) || receipt.MetadataSHA256 != retirementDigestV3(marshal(capture.Operational)) || receipt.DrainedAtBootNS <= 0 {
		t.Fatal("receipt identity differs", err)
	}
	after, err := record.read()
	if err != nil || !scopeRecordZeroV3(after) {
		t.Fatal("completed manifest not cleared", err)
	}
	entries, err := scopeCleanupEntriesV3(area, 0)
	if err != nil || len(entries) != 0 {
		t.Fatal("runtime metadata/resources remain", err)
	}
	stored, err := readScopeRecoveryStoreV3(ctx)
	if err != nil || !scopeRecoveryStoreMatchesV3(stored, nil) {
		t.Fatal("manager store not empty", err)
	}
	if err = waitRoutedCgroupDrainedV3(); err != nil {
		t.Fatal("final descendant retained", err)
	}
	// The fixture-only parent pins belonged to the old MNT, not the gateway
	// receipt. In this invocation their exact zero-byte underlays must be visible.
	for _, name := range []string{"source", "sink"} {
		path := "/fixture/" + name + "/gateway"
		file, e := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if e != nil {
			t.Fatal("fixture parent underlay absent", e)
		}
		var st unix.Stat_t
		valid := unix.Fstat(int(file.Fd()), &st) == nil && st.Mode == unix.S_IFREG|0600 && st.Uid == 0 && st.Gid == 0 && st.Size == 0 && st.Nlink == 1 && fenceNoACLV3(file, false)
		e = file.Close()
		if !valid || e != nil {
			t.Fatal("fixture parent underlay changed", e)
		}
		// Retain the underlay as evidence. Its presence is not drainage authority.
	}
	nativeScopeRetireWriteV3(t, "/fixture/retired.json", proof, 0600, 0, 0)
	t.Log("core Retire verified: exact G1/R2 selection, publication lock, live cgroup drainage, gateway teardown, empty FD store and exact receipt; deployment loader/management activation not qualified")
}

func TestRoutedScopeRetireV3Native(t *testing.T) {
	if os.Getenv("ANDEIVA_SCOPE_RETIRE_NATIVE") != "1" {
		t.Skip("requires authorized two-invocation Debian RootDirectory fixture")
	}
	release, err := os.ReadFile("/etc/os-release")
	if err != nil || !scopeStoreNativeEnvironmentV3(os.Getuid(), os.Geteuid(), os.Getppid(), os.Getenv("CI"), string(release)) {
		t.Fatal("root MAIN, Debian 13, no CI required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	defer cancel()
	var retained *RoutedScopeRecoveryV3
	if os.Getenv("LISTEN_PID") != "" || os.Getenv("LISTEN_FDS") != "" || os.Getenv("LISTEN_FDNAMES") != "" {
		retained, err = nativeScopeRetireTakeV3(ctx)
		if err != nil {
			t.Fatal("strict seven-anchor handoff", err)
		}
		defer retained.Close()
	}
	self, err := os.Executable()
	if err != nil || self != "/fixture/native.test" || trustedRoutedExecutableV3(self) != nil {
		t.Fatal("fixed root-owned fixture executable required")
	}
	if _, err = namespaceID("/proc/self/ns/mnt"); err != nil {
		t.Fatal("current mount namespace unavailable", err)
	}
	// Read manager-owned properties rather than PID1 namespace/root symlinks,
	// which would require an unnecessary CAP_SYS_PTRACE in this fixture.
	if err = nativeScopeRetireRootUnitV3(ctx); err != nil {
		t.Fatal("actual private RootDirectory binding", err)
	}
	if err = scopeStoreNativeUnitV3(ctx); err != nil {
		t.Fatal("fixed transient service properties", err)
	}
	if _, err = readScopeRecoveryUnitV3(ctx); err != nil {
		t.Fatal("actual invocation/nondelegation", err)
	}
	if err = unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		t.Fatal("private mount propagation", err)
	}
	area, err := os.OpenRoot(routedDeploymentRunV3)
	if err != nil {
		t.Fatal(err)
	}
	defer area.Close()
	operational, err := os.OpenRoot(routedRetirementDirectoryV3)
	if err != nil {
		t.Fatal(err)
	}
	defer operational.Close()
	if retained != nil {
		nativeScopeRetireSecondV3(t, ctx, area, operational, retained)
		return
	}
	if _, err = os.Lstat(nativeScopeRetireCaptureV3); !os.IsNotExist(err) {
		t.Fatal("prior evidence without inherited anchors")
	}
	stored, err := readScopeRecoveryStoreV3(ctx)
	if err != nil || !scopeRecoveryStoreMatchesV3(stored, nil) {
		t.Fatal("first invocation store not empty", err)
	}
	nativeScopeRetireFirstV3(t, ctx, area, operational)
}

// This deliberately does not claim coverage of the production eight-FD
// management consumer. The component fixture inherits exactly seven anchors.
func nativeScopeRetireNamesV3(pid, count, names string, self int) ([7]int, error) {
	var out [7]int
	if self <= 1 || pid != strconv.Itoa(self) || count != "7" {
		return out, ErrIdentity
	}
	items := strings.Split(names, ":")
	if len(items) != len(out) {
		return out, ErrIdentity
	}
	for offset, item := range items {
		found := false
		for slot, expected := range scopeRecoveryNamesV3 {
			if item == expected {
				if out[slot] != 0 {
					return [7]int{}, ErrIdentity
				}
				out[slot], found = offset+3, true
				break
			}
		}
		if !found {
			return [7]int{}, ErrIdentity
		}
	}
	return out, nil
}

func nativeScopeRetireTakeV3(ctx context.Context) (*RoutedScopeRecoveryV3, error) {
	indexes, err := nativeScopeRetireNamesV3(os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS"), os.Getenv("LISTEN_FDNAMES"), os.Getpid())
	if err != nil || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getppid() != 1 {
		return nil, ErrIdentity
	}
	var files [7]*os.File
	defer func() {
		for _, file := range files {
			if file != nil {
				_ = file.Close()
			}
		}
	}()
	for i, fd := range indexes {
		unix.CloseOnExec(fd)
		files[i] = os.NewFile(uintptr(fd), "native-retained-scope")
	}
	r, err := OpenRoutedScopeRecoveryV3(ctx, RoutedScopeRecoveryAnchorsV3{files[0], files[1], files[2], files[3], files[4], files[5], files[6]})
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(name)
	}
	return r, nil
}

func TestRoutedScopeRetireV3NativeNames(t *testing.T) {
	names := strings.Join(scopeRecoveryNamesV3[:], ":")
	got, err := nativeScopeRetireNamesV3("77", "7", names, 77)
	if err != nil || got != [7]int{3, 4, 5, 6, 7, 8, 9} {
		t.Fatal("exact anchors refused", err)
	}
	reversed := append([]string(nil), scopeRecoveryNamesV3[:]...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	got, err = nativeScopeRetireNamesV3("77", "7", strings.Join(reversed, ":"), 77)
	if err != nil || got != [7]int{9, 8, 7, 6, 5, 4, 3} {
		t.Fatal("order-independent anchors refused", err)
	}
	for _, bad := range [][3]string{{"78", "7", names}, {"77", "07", names}, {"77", "6", names}, {"77", "8", names + ":" + RoutedScopeManagementFDNameV3}, {"77", "7", strings.Replace(names, scopeRecoveryNamesV3[0], "unknown", 1)}, {"77", "7", strings.Replace(names, scopeRecoveryNamesV3[0], scopeRecoveryNamesV3[1], 1)}} {
		if _, err := nativeScopeRetireNamesV3(bad[0], bad[1], bad[2], 77); err == nil {
			t.Fatal("ambiguous inherited authority accepted")
		}
	}
}

func TestRoutedScopeRetireV3NativeRootGuard(t *testing.T) {
	path := "/var/backups/andeiva-scope-retire.aB0129Zx/root"
	invocation := strings.Repeat("a", 32)
	good := "RootDirectory=" + path + "\nPrivateMounts=yes\nMainPID=77\nInvocationID=" + invocation + "\n"
	if err := nativeScopeRetireRootPropertiesV3([]byte(good), 77, invocation); err != nil {
		t.Fatal("actual shaped private root refused", err)
	}
	for _, path := range []string{"", "/", "/root", "/var/backups/foreign.aB0129Zx/root", "/var/backups/andeiva-scope-retire.aB0129Zx/../root", "/var/backups/andeiva-scope-retire.aB0129Zx/./root", "/var/backups//andeiva-scope-retire.aB0129Zx/root", "/var/backups/andeiva-scope-retire.aB0129Zx/root/", "/var/backups/andeiva-scope-retire.alias/root", "file:///var/backups/andeiva-scope-retire.aB0129Zx/root", "/var/backups/andeiva-scope-retire.%2e%2e00/root", "/var/backups/andeiva-scope-retire.aB0129Zx/root\n"} {
		if nativeScopeRetireRootPathV3(path) {
			t.Fatalf("foreign/aliased root accepted: %q", path)
		}
	}
	for _, raw := range []string{strings.Replace(good, "PrivateMounts=yes", "PrivateMounts=no", 1), strings.Replace(good, "MainPID=77", "MainPID=78", 1), strings.Replace(good, invocation, strings.Repeat("b", 32), 1), good + "RootDirectory=" + path + "\n", good + "Unknown=yes\n", strings.Replace(good, "RootDirectory="+path+"\n", "", 1)} {
		if nativeScopeRetireRootPropertiesV3([]byte(raw), 77, invocation) == nil {
			t.Fatal("uncorrelated manager root properties accepted")
		}
	}
}

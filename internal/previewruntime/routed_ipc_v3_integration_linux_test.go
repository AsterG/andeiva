//go:build linux

package previewruntime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"github.com/AsterG/andeiva/internal/routedactivation"
	"github.com/AsterG/andeiva/internal/routednft"
)

// All storage, reserve banks, G1, reader, IPC and Group code is real. Kernel and
// network I/O use the existing typed fixtures. UID 2000 is logical helper scope;
// Unix peer credentials are the actual non-root test process, not three UIDs.
type routedIPCFixtureV3 struct {
	t               *testing.T
	area            *os.Root
	budget          configpoc.BudgetV2
	auth            *adminauth.Manager
	binding         adminauth.SessionBinding
	legacy, local   configpoc.Revision
	engines         []*configpoc.SimEngine
	pools           configpoc.RuntimePoolsV2
	access          recoveryreserve.ReaderAccessV2
	reader          *configpoc.RoutedSelectionReaderV2
	fullReader      *configpoc.RoutedSelectionReaderV2
	fence           *routedIntegrityFenceV3
	session         *RoutedSessionV3
	integrity       *RoutedRemoteIntegrityV3
	identity        networkexecutor.OwnedNamespaceIdentity
	kernel          *routedTestKernel
	network         *routedTestNetwork
	authority       *RoutedAuthority
	source          *RoutedStoreSourceV3
	remote          *RoutedRemoteAuthority
	reattachConfirm atomic.Bool
	client          *firewallipc.RoutedClientV3
	serverDone      chan error
	service         *configpoc.ServiceV2
}

// Explicit TEST-ONLY offline conversion after every private writer is closed.
func routedIPCSharedAreaV3(t *testing.T, area *os.Root) recoveryreserve.ReaderAccessV2 {
	t.Helper()
	if err := os.Chmod(area.Name(), os.ModeSetgid|0750); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(area.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		mode := os.FileMode(0640)
		if entry.Name() == "checkpoint.lock" {
			mode = 0600
		}
		if err := os.Chmod(filepath.Join(area.Name(), entry.Name()), mode); err != nil {
			t.Fatal(err)
		}
	}
	info, err := area.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return recoveryreserve.ReaderAccessV2{Version: 1, OwnerUID: st.Uid, ReaderGID: st.Gid, Device: st.Dev, Inode: st.Ino}
}

func newRoutedIPCFixtureV3(t *testing.T) *routedIPCFixtureV3 {
	return newRoutedIPCFixtureWithPolicyV3(t, configpoc.SelectionFullHistoryV2)
}

func newRoutedIPCFixtureWithPolicyV3(t *testing.T, readerPolicy configpoc.SelectionReaderPolicyV2) *routedIPCFixtureV3 {
	t.Helper()
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Skip("shared reader requires a non-root Linux test account")
	}
	f := &routedIPCFixtureV3{t: t, budget: configpoc.BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20}}
	enabled := true
	config := configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}}
	for _, rule := range routednft.LabPolicy().Rules {
		config.Rules = append(config.Rules, configpoc.Rule{ID: "retained-" + rule.ID, Enabled: &enabled, Action: rule.Action, Match: &configpoc.Match{Source: rule.Source, Destination: rule.Destination, Protocol: rule.Protocol, SourcePorts: configpoc.PortRange{From: rule.SourcePorts.From, To: rule.SourcePorts.To}, DestinationPorts: configpoc.PortRange{From: rule.DestinationPorts.From, To: rule.DestinationPorts.To}}})
	}
	var err error
	f.legacy, err = configpoc.Canonical(config)
	if err != nil {
		t.Fatal(err)
	}
	local := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}}, {Name: "wan0", Zone: localpolicy.WAN, Addresses: []string{"198.19.0.1"}}}, Services: []localpolicy.Service{}}
	f.local, err = configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &local})
	if err != nil {
		t.Fatal(err)
	}
	areas := [3]*os.Root{routedCoordinatorRoot(t), routedCoordinatorRoot(t), routedCoordinatorRoot(t)}
	f.area = areas[2]
	f.engines = []*configpoc.SimEngine{configpoc.NewSimEngine("import-firewall"), configpoc.NewSimEngine("import-local")}
	var fingerprints [2]configpoc.LegacyFingerprintV2
	for i, revision := range []configpoc.Revision{f.legacy, f.local} {
		old, e := configpoc.Open(areas[i].Name(), []configpoc.Engine{f.engines[i]}, configpoc.Options{Initial: &revision.Config})
		if e != nil {
			t.Fatal(e)
		}
		if e = old.Close(); e != nil {
			t.Fatal(e)
		}
		domain := "firewall"
		if i == 1 {
			domain = "local_services"
		}
		fingerprints[i], err = configpoc.InspectLegacyV2(areas[i], domain)
		if err != nil {
			t.Fatal(err)
		}
	}
	subject, err := configpoc.NewSubjectIDV2()
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	credential := hex.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(credential))
	rev := sha256.Sum256([]byte("ipc-fixture-credential"))
	revision := hex.EncodeToString(rev[:])
	f.auth, err = adminauth.New([]adminauth.Account{{Username: "operator", Role: "admin", CredentialSHA256: hex.EncodeToString(digest[:]), SubjectID: subject, CredentialRevision: revision}}, func(adminauth.Event) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = configpoc.PrepareMigrationV2(f.area, areas[0], areas[1], fingerprints, []configpoc.SubjectV2{{ID: subject, Login: "operator", CredentialRevision: revision}}, nil, f.budget, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	poolAreas := [3]*os.Root{routedCoordinatorRoot(t), routedCoordinatorRoot(t), routedCoordinatorRoot(t)}
	poolPtrs := []**recoveryreserve.PoolV2{&f.pools.Admission, &f.pools.Plan, &f.pools.Emergency}
	roles := []recoveryreserve.RoleV2{recoveryreserve.AdmissionV2, recoveryreserve.PlanV2, recoveryreserve.EmergencyV2}
	capacities := []int{4096, 16384, 8192}
	var profiles [3]recoveryreserve.ProfileV2
	for i, area := range poolAreas {
		*poolPtrs[i], err = recoveryreserve.PrepareV2(area, 18, capacities[i], roles[i])
		if err != nil {
			t.Fatal(err)
		}
		profiles[i], err = (*poolPtrs[i]).Profile()
		if err != nil {
			t.Fatal(err)
		}
	}
	service, err := configpoc.OpenServiceV2(context.Background(), f.area, f.budget, f.auth, []configpoc.Engine{f.engines[0]}, []configpoc.Engine{f.engines[1]})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.PrepareRuntimeReservesV2(context.Background(), f.pools); err != nil {
		t.Fatal(err)
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	policy := routednft.LabPolicy()
	snapshot := networkexecutor.PreparedSnapshot{Version: 1, PlanHash: policy.Network.Hash, Links: []networkexecutor.SnapshotLink{{Index: 2, Name: "lan0", MAC: "02:00:00:00:01:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}}, {Index: 3, Name: "wan0", MAC: "02:00:00:00:02:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}}}, Routes: []networkexecutor.SnapshotRoute{}}
	raw, _ := json.Marshal(snapshot)
	hash := sha256.Sum256(raw)
	snapshot.Hash = hex.EncodeToString(hash[:])
	f.identity = networkexecutor.OwnedNamespaceIdentity{UID: 2000, GID: uint32(os.Getegid()), Namespace: 22, Host: 11, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}
	if f.identity.UID == uint32(os.Geteuid()) {
		f.identity.UID = 2001
	}
	f.kernel = &routedTestKernel{objects: map[routedactivation.Table][]map[string]any{}}
	f.network = &routedTestNetwork{snapshot: snapshot, identity: f.identity}
	f.newAuthority()
	service, err = configpoc.OpenRuntimeServiceV2(context.Background(), f.area, f.budget, f.auth, []configpoc.Engine{f.engines[0]}, []configpoc.Engine{f.engines[1]}, configpoc.RuntimeOptionsV2{Pools: f.pools, GuardDeadlines: true, Routed: f.authority, RoutedIdentity: f.identity})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.PrepareRoutedCompositeV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = service.PrepareSharedReaderV2(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.authority.group.Close(); err != nil {
		t.Fatal(err)
	}
	for _, ptr := range poolPtrs {
		if err = (*ptr).Close(); err != nil {
			t.Fatal(err)
		}
	}
	f.access = routedIPCSharedAreaV3(t, f.area)
	var readPools [3]*recoveryreserve.ReadOnlyPoolV2
	for i, area := range poolAreas {
		access := routedIPCSharedAreaV3(t, area)
		*poolPtrs[i], err = recoveryreserve.OpenSharedV2(area, access)
		if err != nil {
			t.Fatal(err)
		}
		readPools[i], err = recoveryreserve.OpenReadOnlyV2(area, access, profiles[i])
		if err != nil {
			t.Fatal(err)
		}
		p := *poolPtrs[i]
		r := readPools[i]
		t.Cleanup(func() { _ = r.Close(); _ = p.Close() })
	}
	readerOptions := configpoc.SelectionReaderOptionsV2{Access: f.access, Identity: f.identity, Admission: readPools[0], Plan: readPools[1], Emergency: readPools[2], Budget: configpoc.SelectionReadBudgetV2{Entries: 20000, Objects: 16000, Edges: 200000, IOCalls: 2000000, Bytes: 256 << 20, ActiveBytes: 16 << 20, Depth: 128}}
	if readerPolicy == configpoc.SelectionActionAuthorityV2 {
		f.fullReader, err = configpoc.NewRoutedSelectionReaderV2(f.area, readerOptions)
		if err != nil {
			t.Fatal(err)
		}
		// This in-process transport fixture has logical role IDs, not three OS UIDs.
		// The private marker is genuinely owned/preallocated by its actual test UID.
		private := routedCoordinatorRoot(t)
		uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
		if err := prepareRoutedIntegrityFenceV3(private, uid, gid); err != nil {
			t.Fatal(err)
		}
		f.fence, err = openRoutedIntegrityFenceV3(private, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.fence.Close() })
	}

	readerOptions.Policy = readerPolicy
	f.reader, err = configpoc.NewRoutedSelectionReaderV2(f.area, readerOptions)
	if err != nil {
		t.Fatal(err)
	}
	f.source, err = NewRoutedStoreSourceV3(f.reader)
	if err != nil {
		t.Fatal(err)
	}
	f.newAuthority()
	f.connect()
	f.open()
	_, token, err := f.auth.Login("operator", credential)
	if err != nil {
		t.Fatal(err)
	}
	f.binding, err = f.auth.ResolveSession(token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f.service != nil {
			_ = f.service.Close()
		}
		f.disconnect()
		_ = f.authority.group.Close()
	})
	return f
}

func (f *routedIPCFixtureV3) newAuthority() {
	f.t.Helper()
	f.session = nil
	options := routedactivation.Options{Legacy: f.legacy}
	for _, link := range f.network.snapshot.Links {
		options.ObservedBindings = append(options.ObservedBindings, networkplan.Binding{Name: link.Name, HardwareAddress: link.MAC})
	}
	var err error
	f.authority, err = NewRoutedAuthority(f.kernel, f.network, &routedTestListeners{}, options, f.identity)
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *routedIPCFixtureV3) connect() {
	f.t.Helper()
	var err error
	if f.session == nil {
		source := routedIPCObservedSourceV3{RoutedStoreSourceV3: f.source, t: f.t}
		if f.fullReader != nil {
			f.session, err = NewRoutedIntegritySessionV3(f.authority, source, f.fullReader, f.fence)
		} else {
			f.session, err = NewRoutedSessionV3(f.authority, source)
		}
		if err != nil {
			f.t.Fatal(err)
		}
	}
	session := f.session
	a, b := routedUnixPairV3(f.t)
	uid, gid, pid := uint32(os.Geteuid()), uint32(os.Getegid()), int32(os.Getpid())
	f.serverDone = make(chan error, 1)
	go func() {
		f.serverDone <- session.ServeInheritedRoutedV3(context.Background(), b, uid, gid, pid, f.identity.RunID)
	}()
	connect := ConnectInheritedRoutedV3
	if f.fullReader != nil {
		connect = ConnectInheritedRoutedIntegrityV3
	}
	f.client, err = connect(context.Background(), a, uid, gid, pid, f.identity.RunID, f.identity.Namespace)
	if err != nil {
		f.t.Fatal("handshake", err)
	}
	if f.fullReader != nil {
		f.integrity, err = NewRoutedRemoteIntegrityV3(f.client)
		if err != nil {
			f.t.Fatal(err)
		}
	}
	f.remote, err = NewRoutedRemoteAuthority(f.client, f.identity)
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *routedIPCFixtureV3) disconnect() {
	if f.remote != nil {
		_ = f.remote.Close()
		<-f.serverDone
		f.remote = nil
	}
}
func (f *routedIPCFixtureV3) open() {
	f.t.Helper()
	if f.remote == nil {
		f.t.Fatal("writer opened before handshake")
	}
	var err error
	options := configpoc.RuntimeOptionsV2{SharedReader: &f.access, Pools: f.pools, GuardDeadlines: true, Routed: &routedIPCConfirmHookV3{RoutedRemoteAuthority: f.remote, fixture: f}, RoutedIdentity: f.identity, BootID: f.identity.BootID}
	if f.integrity != nil {
		options.Integrity = routedIPCObservedIntegrityV3{RoutedRemoteIntegrityV3: f.integrity, t: f.t}
	}
	started := time.Now()
	f.service, err = configpoc.OpenRuntimeServiceV2(context.Background(), f.area, f.budget, f.auth, []configpoc.Engine{f.engines[0]}, []configpoc.Engine{f.engines[1]}, options)
	f.t.Log("writer open", time.Since(started), err)
	if err != nil {
		f.t.Fatal("shared writer", err)
	}
}
func (f *routedIPCFixtureV3) run(request configpoc.OperationRequestV2) configpoc.ResultV2 {
	f.t.Helper()
	before, beforeErr := f.service.Status(f.binding)
	f.t.Log("before operation", request.Kind, "pending", before.Confirmation != nil, "recovery", before.RecoveryRequired, "status error", beforeErr)
	if f.integrity != nil && request.Kind != configpoc.OpConfirm {
		// Explicit trusted maintenance between quiescent workflow steps. Periodic
		// scheduling/threshold behavior has its own tests; no scan runs in a lease.
		started := time.Now()
		if err := f.service.InspectRuntimeV1(context.Background()); err != nil {
			f.t.Fatal("quiescent full inspection", request.Kind, time.Since(started), err)
		}
	}
	status, err := f.service.Status(f.binding)
	if err != nil {
		f.t.Fatal(err)
	}
	ns, err := f.service.Namespace(f.binding, "routed", time.Hour)
	if err != nil {
		f.t.Fatal(err)
	}
	op, err := f.service.Admit(f.binding, ns.ID, status.GlobalGeneration, request)
	if err != nil {
		f.t.Fatal(request.Kind, "admit", err)
	}
	result, err := f.service.Execute(context.Background(), f.binding, op.ID)
	if err != nil {
		select {
		case serverErr := <-f.serverDone:
			f.t.Log("helper session exit:", serverErr)
			f.serverDone <- serverErr
		default:
		}
		f.t.Fatal(request.Kind, "execute", err)
	}
	if request.Kind == configpoc.OpConfirm {
		if result.Operation.State != "final" || result.Operation.Outcome == nil || result.Operation.Outcome.Code != "applied" || result.Operation.Outcome.ErrorCode != "" || result.Current.Confirmation != nil || result.Current.RecoveryRequired {
			f.t.Fatal("confirm did not finish without pending/recovery", result.Operation.State, result.Current.Confirmation != nil, result.Current.RecoveryRequired)
		}
		f.t.Log("confirm final applied; pending/recovery false")
	}
	return result
}

type routedIPCObservedIntegrityV3 struct {
	*RoutedRemoteIntegrityV3
	t *testing.T
}

func (i routedIPCObservedIntegrityV3) Inspect(ctx context.Context, expected configpoc.SelectionReferenceV2) (configpoc.IntegrityResultV1, error) {
	started := time.Now()
	result, err := i.RoutedRemoteIntegrityV3.Inspect(ctx, expected)
	i.t.Log("integrity inspection", time.Since(started), "state", result.State, "selection matches", result.Selection == expected, "error", err, "context", ctx.Err())
	return result, err
}

type routedIPCObservedSourceV3 struct {
	*RoutedStoreSourceV3
	t *testing.T
}

func (s routedIPCObservedSourceV3) PrepareView(ctx context.Context) (RoutedPreparationViewV3, error) {
	start := time.Now()
	value, err := s.RoutedStoreSourceV3.PrepareView(ctx)
	s.t.Log("helper PrepareView", time.Since(start), err)
	return value, err
}

func (s routedIPCObservedSourceV3) Resolve(ctx context.Context, ref firewallipc.RoutedReferenceV3, purpose string) (configpoc.RoutedSelectedPlanV1, error) {
	start := time.Now()
	value, err := s.RoutedStoreSourceV3.Resolve(ctx, ref, purpose)
	s.t.Log("helper Resolve", purpose, time.Since(start), err)
	return value, err
}

func TestRoutedIPCV3SharedStoreLifecycle(t *testing.T) {
	testRoutedIPCV3SharedStoreLifecycle(t, configpoc.SelectionActionAuthorityV2)
}
func TestRoutedIPCV3DefaultFullReaderStartup(t *testing.T) {
	f := newRoutedIPCFixtureWithPolicyV3(t, configpoc.SelectionFullHistoryV2)
	if f.fullReader != nil || f.integrity != nil {
		t.Fatal("default full-reader profile changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	view, err := f.reader.PrepareCurrentView(ctx)
	if err != nil || view.Startup.Firewall.Hash != f.legacy.Hash || len(view.Startup.Firewall.Config.Rules) != 2 {
		t.Fatal("default full startup", err)
	}
}

func testRoutedIPCV3SharedStoreLifecycle(t *testing.T, readerPolicy configpoc.SelectionReaderPolicyV2) {
	t.Helper()
	f := newRoutedIPCFixtureWithPolicyV3(t, readerPolicy)
	ctx := context.Background()
	data, present, err := f.kernel.Observe(ctx, routedactivation.LegacyTable)
	if err != nil || !present {
		t.Fatal(err)
	}
	if _, err = firewallnft.VerifyObservation(data, f.legacy); err != nil || len(f.legacy.Config.Rules) != 2 || f.network.calls != 0 || f.network.active {
		t.Fatal("Boot4 actual two rules/no L3", err)
	}
	for _, engine := range f.engines {
		engine.Drift(strings.Repeat("f", 64))
	}
	for _, domain := range []string{"firewall", "local_services"} {
		if _, err := f.service.Namespace(f.binding, domain, time.Hour); !errors.Is(err, configpoc.ErrDenied) {
			t.Fatal("legacy writer fell through", err)
		}
	}
	edited := f.legacy.Config
	edited.Rules = append([]configpoc.Rule(nil), edited.Rules...)
	edited.Rules[0].Action = "deny"
	f.run(configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &edited})
	f.run(configpoc.OperationRequestV2{Kind: configpoc.OpValidate})
	seconds := uint64(30)
	committed := f.run(configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds})
	f.run(configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: committed.Operation.ID, Target: committed.Current.RunningRevision})
	saved := f.run(configpoc.OperationRequestV2{Kind: configpoc.OpSave})
	if f.network.calls != 0 {
		t.Fatal("schema4 configured L3")
	}
	policy := routednft.LabPolicy()
	target := configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy}
	f.run(configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &target})
	f.run(configpoc.OperationRequestV2{Kind: configpoc.OpValidate})
	pending := f.run(configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds})
	receipt, _, err := f.remote.Observe(ctx)
	if err != nil || !f.network.active || !receipt.Deadline.Equal(pending.Current.Confirmation.Deadline) {
		t.Fatal("original pending deadline", err)
	}
	reference, err := f.reader.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ref := firewallipc.RoutedReferenceV3{Work: reference.WorkHash, Lineage: reference.Lineage, Generation: "1"}
	plan, err := f.reader.Resolve(ctx, reference, configpoc.SelectionMatchTargetV2)
	if err != nil {
		t.Fatal(err)
	}
	ref.Generation = strconv.FormatUint(plan.Reference().Generation, 10)
	calls := len(f.kernel.batches)
	if _, err := f.source.Resolve(ctx, ref, "arm"); err == nil {
		t.Fatal("pending work armed again")
	}
	wrong := ref
	wrong.Work = strings.Repeat("e", 64)
	if _, err := f.source.Resolve(ctx, wrong, "match_target"); err == nil || len(f.kernel.batches) != calls {
		t.Fatal("wrong work accepted")
	}
	f.run(configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: pending.Operation.ID, Target: pending.Current.RunningRevision})
	if err := f.service.Close(); err != nil {
		t.Fatal(err)
	}
	f.disconnect()
	if err := f.authority.group.Close(); err != nil {
		t.Fatal(err)
	}
	f.newAuthority()
	f.connect()
	f.open()
	effective, err := f.service.RoutedEffective(ctx, f.binding)
	if err != nil || !effective.Consistent || !f.network.active {
		t.Fatal("confirmed helper restart", err)
	}
	rolled := f.run(configpoc.OperationRequestV2{Kind: configpoc.OpRollback, Target: saved.Current.StartupRevision, ConfirmSeconds: &seconds})
	if f.network.active {
		t.Fatal("inverse did not restore exact no-network baseline")
	}
	f.run(configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: rolled.Operation.ID, Target: rolled.Current.RunningRevision})
}

// Test-only interception occurs after the durable Confirm Intent is selected,
// but before its effect RPC; Attach still traverses the real authenticated IPC.
type routedIPCConfirmHookV3 struct {
	*RoutedRemoteAuthority
	fixture *routedIPCFixtureV3
}

func (h *routedIPCConfirmHookV3) Confirm(ctx context.Context, p configpoc.RoutedSelectedPlanV1) error {
	f := h.fixture
	if f.reattachConfirm.CompareAndSwap(true, false) {
		original := f.session.integrity.anchor
		before, err := f.reader.CaptureReferenceV1(ctx)
		if err != nil {
			return err
		}
		receipt, hash, err := f.authority.Observe(ctx)
		if err != nil {
			return err
		}
		if err := f.fence.MarkBlocked(); err != nil {
			return err
		}
		if err := f.integrity.Attach(ctx, before); err != nil {
			return err
		}
		after, err := f.reader.CaptureReferenceV1(ctx)
		if err != nil {
			return err
		}
		afterReceipt, afterHash, err := f.authority.Observe(ctx)
		if err != nil {
			return err
		}
		f.source.coldMu.Lock()
		captured := f.source.cold.Reference()
		f.source.coldMu.Unlock()
		if before != after || receipt != afterReceipt || hash != afterHash || !receipt.Deadline.Equal(p.Deadline()) || f.session.integrity.anchor != original || captured != original {
			f.t.Error("reattachment changed selected tuple, deadline, readback or original anchor")
		}
	}
	return h.RoutedRemoteAuthority.Confirm(ctx, p)
}
